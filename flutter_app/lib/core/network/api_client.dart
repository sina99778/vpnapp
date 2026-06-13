import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dio/dio.dart';
import 'package:dio/io.dart';

import '../config/app_config.dart';
import '../errors/failures.dart';
import '../storage/secure_store.dart';

/// The single HTTP gateway to the middleware. Enforces three things every
/// request, no exceptions:
///   1. TLS certificate pinning (rejects MITM even with a trusted system root).
///   2. Bearer access token attached; transparent refresh on 401.
///   3. All transport errors normalised to typed [AppFailure]s.
class ApiClient {
  ApiClient({required SecureStore store, Dio? dio})
      : _store = store,
        _dio = dio ?? Dio() {
    _dio.options
      ..baseUrl = AppConfig.apiBaseUrl
      ..connectTimeout = const Duration(seconds: 10)
      ..receiveTimeout = const Duration(seconds: 20)
      ..sendTimeout = const Duration(seconds: 15)
      ..headers['content-type'] = 'application/json';

    _installPinning(_dio);
    _dio.interceptors.add(_AuthInterceptor(_store, _refreshDio()));
  }

  final Dio _dio;
  final SecureStore _store;

  /// GET/POST helpers that return a decoded JSON map or throw [AppFailure].
  Future<Map<String, dynamic>> postJson(
    String path, {
    Object? body,
    bool auth = true,
    CancelToken? cancelToken,
  }) async {
    try {
      final res = await _dio.post<dynamic>(
        path,
        data: body,
        cancelToken: cancelToken,
        options: Options(extra: {_kRequiresAuth: auth}),
      );
      return _asMap(res.data);
    } on DioException catch (e) {
      throw _mapDioError(e);
    }
  }

  Future<Map<String, dynamic>> getJson(
    String path, {
    bool auth = true,
    CancelToken? cancelToken,
  }) async {
    try {
      final res = await _dio.get<dynamic>(
        path,
        cancelToken: cancelToken,
        options: Options(extra: {_kRequiresAuth: auth}),
      );
      return _asMap(res.data);
    } on DioException catch (e) {
      throw _mapDioError(e);
    }
  }

  // --- pinning ---------------------------------------------------------------

  void _installPinning(Dio dio) {
    final pins = AppConfig.tlsPinsBase64;
    dio.httpClientAdapter = IOHttpClientAdapter(
      // validateCertificate runs for EVERY peer cert (valid or not), which is
      // exactly what pinning needs — unlike badCertificateCallback, which only
      // fires on chain failures.
      validateCertificate: (X509Certificate? cert, String host, int port) {
        if (pins.isEmpty) {
          // Dev/staging without pins: defer to normal chain validation, which
          // dio still performs. We only reach here for otherwise-valid certs.
          return true;
        }
        if (cert == null) return false;
        final fp = base64.encode(crypto.sha256.convert(cert.der).bytes);
        // Constant set membership; rotation handled by shipping current+next.
        return pins.contains(fp);
      },
    );
  }

  /// A second Dio with the SAME pinning but NO auth interceptor, used by the
  /// interceptor to refresh tokens without infinite recursion.
  Dio _refreshDio() {
    final d = Dio(BaseOptions(baseUrl: AppConfig.apiBaseUrl));
    _installPinning(d);
    return d;
  }

  // --- helpers ---------------------------------------------------------------

  static const _kRequiresAuth = 'requiresAuth';

  Map<String, dynamic> _asMap(dynamic data) {
    if (data is Map<String, dynamic>) return data;
    if (data is String && data.isNotEmpty) {
      final decoded = jsonDecode(data);
      if (decoded is Map<String, dynamic>) return decoded;
    }
    throw const PayloadFailure('Unexpected server response.');
  }

  AppFailure _mapDioError(DioException e) {
    // A pin mismatch surfaces as a handshake/connection error.
    final isHandshake = e.error is HandshakeException ||
        e.error is TlsException ||
        (e.error is SocketException &&
            (e.error as SocketException).message.toLowerCase().contains('certificate'));
    if (isHandshake) {
      return PinningFailure(cause: e.error);
    }

    switch (e.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.receiveTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.connectionError:
        return NetworkFailure(cause: e);
      case DioExceptionType.badCertificate:
        return PinningFailure(cause: e);
      case DioExceptionType.badResponse:
        final code = e.response?.statusCode ?? 0;
        final body = e.response?.data;
        final apiCode = body is Map ? body['code'] as String? : null;
        final msg = body is Map ? (body['message'] as String?) : null;
        if (code == 401 || code == 403) {
          return AuthFailure(msg ?? 'Session expired — please sign in again.', cause: e);
        }
        return ApiFailure(
          msg ?? 'Request failed ($code).',
          statusCode: code,
          code: apiCode,
          cause: e,
        );
      case DioExceptionType.cancel:
      case DioExceptionType.unknown:
        return NetworkFailure('Something went wrong. Please try again.', cause: e);
    }
  }
}

/// Attaches the access token and performs a one-shot refresh on 401.
class _AuthInterceptor extends Interceptor {
  _AuthInterceptor(this._store, this._refreshDio);

  final SecureStore _store;
  final Dio _refreshDio;
  bool _refreshing = false;

  @override
  Future<void> onRequest(RequestOptions options, RequestInterceptorHandler handler) async {
    final requiresAuth = options.extra[ApiClient._kRequiresAuth] != false;
    if (requiresAuth) {
      final token = await _store.accessToken;
      if (token != null) options.headers['authorization'] = 'Bearer $token';
    }
    handler.next(options);
  }

  @override
  Future<void> onError(DioException err, ErrorInterceptorHandler handler) async {
    final status = err.response?.statusCode;
    final isAuthCall = err.requestOptions.path.contains('/auth/');
    if (status != 401 || isAuthCall || _refreshing) {
      return handler.next(err);
    }

    _refreshing = true;
    try {
      final refresh = await _store.refreshToken;
      if (refresh == null) return handler.next(err);

      final res = await _refreshDio.post<dynamic>(
        '/api/v1/auth/refresh',
        data: {'refreshToken': refresh},
      );
      final data = res.data;
      if (data is! Map) return handler.next(err);

      await _store.setTokens(
        access: data['accessToken'] as String,
        refresh: data['refreshToken'] as String,
      );

      // Replay the original request once with the new token.
      final retry = err.requestOptions
        ..headers['authorization'] = 'Bearer ${data['accessToken']}';
      final cloned = await _refreshDio.fetch<dynamic>(retry);
      return handler.resolve(cloned);
    } catch (_) {
      await _store.clearAuth();
      return handler.next(err);
    } finally {
      _refreshing = false;
    }
  }
}
