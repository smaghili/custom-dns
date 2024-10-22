# Custom DNS Server Setup Guide
این راهنما نحوه راه‌اندازی و پیکربندی سرور DNS سفارشی را توضیح می‌دهد. 

⚠️ **نکته مهم: تمامی دستورات زیر باید در سرور ایران اجرا شوند.**

## پیش‌نیازها
- دسترسی root به سرور ایران
- دسترسی به سرور خارج
- اتصال اینترنت پایدار

## مراحل نصب و راه‌اندازی (در سرور ایران)

### 1. برقراری تانل SSH
در سرور ایران، دستور زیر را اجرا کنید تا تانل SSH بین سرور ایران و سرور خارج برقرار شود:
```bash
curl -o install.sh https://raw.githubusercontent.com/smaghili/sshtunnel/main/install.sh && chmod +x install.sh && ./install.sh
```

### 2. نصب سرور DNS
پس از برقراری تانل، در همان سرور ایران دستور زیر را اجرا کنید:
```bash
curl -o install.sh https://raw.githubusercontent.com/smaghili/custom-dns/main/install.sh && chmod +x install.sh && ./install.sh
```

### 3. راه‌اندازی سرویس DNS
در سرور ایران، سرویس DNS را با دستور زیر راه‌اندازی کنید:
```bash
sudo dns --port 53 --whitelist-file domains.txt --forward-dns "10.202.10.10,37.236.64.218"
```

## پیکربندی

### پارامترهای دستور راه‌اندازی
- `--port 53`: پورت پیش‌فرض DNS (معمولاً نیازی به تغییر ندارد)
- `--whitelist-file domains.txt`: مسیر فایل لیست دامنه‌های مجاز
- `--forward-dns`: لیست DNS سرورهای forward (با کاما جدا می‌شوند)

### مدیریت لیست سفید دامنه‌ها
فایل `domains.txt` در سرور ایران در مسیر `/opt/dns/domains.txt` قرار دارد. می‌توانید این فایل را ویرایش کرده و دامنه‌های مورد نظر را اضافه یا حذف کنید.

#### الگوهای قابل استفاده در domains.txt:
1. دامنه دقیق:
   ```
   example.com
   ```
2. تمام زیردامنه‌های یک دامنه:
   ```
   .intel.com
   ```
   این الگو تمام زیردامنه‌های intel.com را پوشش می‌دهد (مانند download.intel.com, support.intel.com)
3. تمام دامنه‌ها با یک نام خاص:
   ```
   .intel.
   ```
   این الگو تمام دامنه‌ها و زیردامنه‌های حاوی "intel" را پوشش می‌دهد

### پیکربندی DNS های Forward
در پارامتر `--forward-dns` می‌توانید یک یا چند DNS سرور را مشخص کنید. ترافیک دامنه‌هایی که در لیست سفید نیستند از طریق این DNS سرورها هدایت می‌شوند.

مثال:
```bash
--forward-dns "10.202.10.10,37.236.64.218,8.8.8.8"
```

## مدیریت سرویس (در سرور ایران)
تمامی دستورات مدیریتی زیر باید در سرور ایران اجرا شوند:
```bash
# مشاهده وضعیت سرویس
systemctl status custom-dns
# متوقف کردن سرویس
systemctl stop custom-dns
# راه‌اندازی مجدد سرویس
systemctl restart custom-dns
# مشاهده لاگ‌ها
tail -f /var/log/custom-dns.log
tail -f /var/log/custom-dns.error.log
```

## تغییر تنظیمات (در سرور ایران)
برای تغییر هر یک از تنظیمات (مانند DNS های forward) کافیست در سرور ایران دستور راه‌اندازی را با پارامترهای جدید اجرا کنید:
```bash
sudo dns --port 53 --whitelist-file domains.txt --forward-dns "10.202.10.10,8.8.8.8"
```

## عیب‌یابی (در سرور ایران)
در صورت بروز مشکل، این دستورات را در سرور ایران اجرا کنید:

1. بررسی لاگ‌ها:
   ```bash
   journalctl -u custom-dns -n 50 --no-pager
   ```
2. بررسی فایل‌های لاگ:
   ```bash
   tail -f /var/log/custom-dns.log
   tail -f /var/log/custom-dns.error.log
   ```
3. اطمینان از دسترسی به پورت 53:
   ```bash
   netstat -tulpn | grep :53
   ```

## پشتیبانی
برای گزارش مشکلات یا پیشنهادات به صفحه GitHub پروژه مراجعه کنید:
- [Custom DNS Server Repository](https://github.com/smaghili/custom-dns)
- [SSH Tunnel Repository](https://github.com/smaghili/sshtunnel)

برای ارتباط با من:
https://t.me/sma16719
