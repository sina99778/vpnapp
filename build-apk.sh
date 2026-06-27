#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo -e "\033[1;31m❌ خطا: آدرس API سرور وارد نشده است.\033[0m"
    echo -e "نحوه استفاده: ./build-apk.sh <API_URL>"
    echo -e "مثال: ./build-apk.sh http://1.2.3.4:3000/api/v1"
    exit 1
fi

API_URL="$1"

echo -e "\033[1;34m==========================================\033[0m"
echo -e "\033[1;32m🚀 در حال بیلد کردن اپلیکیشن اندروید (APK) با Docker...\033[0m"
echo -e "\033[1;33m🔗 آدرس API تنظیم شده: $API_URL\033[0m"
echo -e "⚠️ این فرآیند ممکن است چند دقیقه زمان ببرد (بسته به سرعت اینترنت سرور شما)."
echo -e "\033[1;34m==========================================\033[0m"

# ورود به پوشه فلاتر
cd flutter_app

# اجرای بیلد داخل یک کانتینر موقت فلاتر
docker run --rm -v "$(pwd):/app" -w /app ghcr.io/cirruslabs/flutter:stable bash -c "
    git config --global --add safe.directory /app
    flutter pub get
    flutter build apk --release --dart-define=API_BASE_URL=$API_URL
"

# تغییر مالکیت فایل خروجی به کاربر فعلی سرور (چون داکر به عنوان root فایل را میسازد)
sudo chown -R $USER:$USER build/ || true

echo -e "\033[1;34m==========================================\033[0m"
echo -e "\033[1;32m✅ بیلد با موفقیت انجام شد!\033[0m"
echo -e "\033[1;36m📁 فایل نصب اندروید در مسیر زیر قرار دارد:\033[0m"
echo -e "   flutter_app/build/app/outputs/flutter-apk/app-release.apk"
echo -e "\033[1;34m==========================================\033[0m"
