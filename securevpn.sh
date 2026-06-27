#!/bin/bash
# SecureVPN Interactive CLI Manager

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

show_menu() {
    clear
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${GREEN}    🛡️ SecureVPN Middleware Manager    ${NC}"
    echo -e "${BLUE}=======================================${NC}"
    echo "1) 🩺 Doctor (عیب‌یاب سیستم)"
    echo "2) 🚀 Deploy / Start Services (اجرای سرویس‌ها)"
    echo "3) 🛑 Stop Services (توقف سرویس‌ها)"
    echo "4) 🔄 Update System (بروزرسانی کل سیستم)"
    echo "5) 🌐 Rebuild Web Panel (بیلد مجدد پنل وب)"
    echo "6) 📜 View API Logs (مشاهده لاگ‌های بک‌اند)"
    echo "7) 📜 View Web Dashboard Logs (مشاهده لاگ‌های داشبورد)"
    echo "0) ❌ Exit (خروج)"
    echo -e "${BLUE}=======================================${NC}"
    echo -n "Choose an option: "
}

run_doctor() {
    echo -e "\n${YELLOW}Running Diagnostics (در حال بررسی سلامت سیستم)...${NC}\n"
    
    # 1. Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "🐳 Docker: ${RED}Not Installed! (داکر نصب نیست)${NC}"
    else
        echo -e "🐳 Docker: ${GREEN}OK${NC}"
    fi

    # 2. Check .env
    if [ ! -f "backend/.env" ]; then
        echo -e "📄 backend/.env: ${RED}Missing! (فایل تنظیمات وجود ندارد)${NC} (Run install.sh)"
    else
        echo -e "📄 backend/.env: ${GREEN}OK${NC}"
    fi

    # 3. Check Ports
    if command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":3000 "; then
            echo -e "🔌 Port 3000 (API): ${RED}IN USE! (پورت ۳۰۰۰ اشغال است)${NC}"
        else
            echo -e "🔌 Port 3000 (API): ${GREEN}FREE${NC}"
        fi
        if netstat -tuln | grep -q ":3001 "; then
            echo -e "🔌 Port 3001 (Web): ${RED}IN USE! (پورت ۳۰۰۱ اشغال است)${NC}"
        else
            echo -e "🔌 Port 3001 (Web): ${GREEN}FREE${NC}"
        fi
    else
        echo -e "🔌 Ports: ${YELLOW}Skipped (netstat not found)${NC}"
    fi

    # 4. Check Disk Space
    FREE_SPACE=$(df -h . | awk 'NR==2 {print $4}')
    echo -e "💾 Free Space: ${GREEN}${FREE_SPACE}${NC}"

    echo -e "\nPress Enter to return..."
    read
}

while true; do
    show_menu
    read choice
    case $choice in
        1)
            run_doctor
            ;;
        2)
            echo -e "${YELLOW}Starting services (API + Web Panel)...${NC}"
            docker compose up -d
            echo -e "${GREEN}Done! (انجام شد)${NC}"
            echo -e "\n🌐 ${BLUE}Web Dashboard:${NC} http://localhost:3001"
            echo -e "🔗 ${BLUE}API Endpoint:${NC}  http://localhost:3000"
            echo -e "\nPress Enter to return..."
            read
            ;;
        3)
            echo -e "${YELLOW}Stopping services...${NC}"
            docker compose stop
            echo -e "${GREEN}Done!${NC}"
            sleep 2
            ;;
        4)
            echo -e "${YELLOW}Pulling latest updates...${NC}"
            git pull origin main
            echo -e "${YELLOW}Rebuilding and starting...${NC}"
            docker compose up -d --build
            echo -e "${GREEN}Update completed!${NC}"
            sleep 2
            ;;
        5)
            echo -e "${YELLOW}Rebuilding Web Panel... (در حال بیلد مجدد پنل وب)${NC}"
            docker compose up -d --build web
            echo -e "${GREEN}Web Panel rebuilt successfully!${NC}"
            sleep 2
            ;;
        6)
            docker compose logs -f api
            ;;
        7)
            docker compose logs -f web
            ;;
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            sleep 1
            ;;
    esac
done
