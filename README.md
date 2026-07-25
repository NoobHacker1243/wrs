# wrs

🇮🇷 Persian Version

➡️ برای مشاهده نسخه فارسی، به پایین این صفحه بروید.

WSR — Web Security Recon

WSR is a powerful, modular, and modern Python-based command-line reconnaissance framework designed to automate the collection and organization of technical information about web targets.

Built with performance, extensibility, and usability in mind, WSR combines multiple reconnaissance tools into a unified workflow while presenting results through a professional terminal interface, live dashboard, and comprehensive reporting system.

The project focuses on delivering clean architecture, high performance, and an exceptional terminal user experience without sacrificing flexibility.


---

Features

Modern terminal interface (CLI/TUI)

Professional live dashboard

Real-time progress tracking

Live execution statistics

Animated terminal interface

Multi-language support (English / Persian)

Interactive menus

Professional logging system

Automatic session management

Resume interrupted scans

Execution history

Modular plugin architecture

Theme support

Rich final reports

Multiple report formats

Configuration management

Optimized execution engine

Concurrent task management

Automatic dependency checking

Automatic environment detection

Responsive terminal layout

Detailed execution timeline

Clean and maintainable architecture



---

Information Collection

WSR can organize information such as:

Domains

Subdomains

Live Hosts

URLs

Technologies

HTTP Headers

Cookies

Redirect Chains

DNS Records

SSL/TLS Information

Open Ports

Running Services

CDN Detection

WAF Detection

Interesting Files

Response Metadata

Network Information

Execution Statistics


The available information depends on the enabled modules and installed external tools.


---

Live Dashboard

During execution WSR provides a continuously updating dashboard containing information such as:

Current task

Current tool

Overall progress

Execution time

Estimated remaining time (when measurable)

CPU usage

Memory usage

Disk usage

Network statistics

Active processes

Queue status

Success count

Warning count

Error count

Timeout count

Session information


Only real collected information is displayed.


---

Reports

WSR automatically generates detailed reports in multiple formats:

TXT

JSON

HTML

Markdown

CSV


Reports include execution statistics, collected information, timelines, generated artifacts, command history, and structured summaries.


---

Architecture

The project follows modern software engineering principles:

Modular architecture

Clean Code

SOLID

DRY

Type Hints

Docstrings

Professional Exception Handling

Extensible Plugin System

Maintainable Codebase

High Readability



---

Performance

Designed for efficient execution using modern Python techniques including:

asyncio

ThreadPoolExecutor

Queue Management

Connection Pooling

Intelligent Retry Logic

Lazy Loading

Resource Management

Parallel Task Scheduling



---

User Experience

WSR emphasizes a professional Linux terminal experience inspired by modern command-line applications while maintaining its own visual identity.

The interface includes:

Responsive layouts

Live updates

Professional color themes

Animated components

Structured panels

Detailed status views

Minimal unnecessary output



---

Requirements

Python 3.10+

Linux

Kali Linux

Debian

Ubuntu

Fedora

Arch Linux

WSL

Termux



---

Project Goals

Professional architecture

Reliable execution

High performance

Excellent terminal UX

Modular design

Easy extensibility

Comprehensive reporting

Clean implementation

Long-term maintainability

🇺🇸 English Version


 
WSR — شناسایی و تحلیل وب

WSR یک چارچوب قدرتمند، ماژولار و مدرن مبتنی بر Python برای خط فرمان است که با هدف خودکارسازی جمع‌آوری، سازمان‌دهی و تحلیل اطلاعات فنی اهداف وب توسعه یافته است.

این پروژه با تمرکز بر عملکرد بالا، معماری قابل توسعه و تجربه کاربری حرفه‌ای، مجموعه‌ای از ابزارهای مختلف را در قالب یک گردش‌کار یکپارچه ترکیب می‌کند و نتایج را از طریق رابط کاربری پیشرفته ترمینال، داشبورد زنده و سیستم گزارش‌دهی جامع نمایش می‌دهد.

هدف WSR ارائه یک ساختار تمیز، سریع، پایدار و قابل نگهداری است که علاوه بر قدرت فنی، تجربه‌ای حرفه‌ای در محیط ترمینال لینوکس فراهم کند.


---

قابلیت‌ها

رابط کاربری مدرن CLI/TUI

داشبورد زنده و پویا

نمایش لحظه‌ای وضعیت اجرای عملیات

نمایش آمار زنده

انیمیشن‌های روان در ترمینال

پشتیبانی از زبان فارسی و انگلیسی

منوهای تعاملی

سیستم حرفه‌ای ثبت رویدادها (Logging)

مدیریت خودکار نشست‌ها (Session)

ادامه اجرای عملیات پس از توقف (Resume)

تاریخچه اجراها

معماری افزونه‌پذیر (Plugin System)

پشتیبانی از چندین قالب ظاهری (Theme)

گزارش‌های کامل و ساختاریافته

خروجی در قالب‌های مختلف

سیستم تنظیمات قابل ذخیره

موتور اجرای بهینه

مدیریت همزمان پردازش‌ها

بررسی خودکار وابستگی‌ها

تشخیص خودکار محیط اجرا

رابط واکنش‌گرا متناسب با اندازه ترمینال

نمایش دقیق روند اجرای عملیات

معماری تمیز و قابل توسعه



---

اطلاعات قابل جمع‌آوری

WSR می‌تواند اطلاعاتی از جمله موارد زیر را جمع‌آوری و سازمان‌دهی کند:

دامنه‌ها

زیردامنه‌ها

میزبان‌های فعال

آدرس‌های URL

فناوری‌های استفاده‌شده

هدرهای HTTP

کوکی‌ها

زنجیره ریدایرکت‌ها

رکوردهای DNS

اطلاعات SSL/TLS

پورت‌های باز

سرویس‌های در حال اجرا

تشخیص CDN

تشخیص WAF

فایل‌های قابل توجه

اطلاعات پاسخ‌های سرور

اطلاعات شبکه

آمار اجرای عملیات


اطلاعات قابل جمع‌آوری بسته به ابزارهای نصب‌شده و ماژول‌های فعال ممکن است متفاوت باشد.


---

داشبورد زنده

در زمان اجرای برنامه، داشبورد زنده اطلاعات مختلفی را به‌صورت لحظه‌ای نمایش می‌دهد، از جمله:

وظیفه در حال اجرا

ابزار فعال

میزان پیشرفت

زمان سپری‌شده

زمان تخمینی باقی‌مانده (در صورت امکان محاسبه)

میزان مصرف پردازنده

میزان مصرف حافظه

میزان استفاده از دیسک

آمار شبکه

پردازش‌های فعال

وضعیت صف اجرا

تعداد عملیات موفق

تعداد هشدارها

تعداد خطاها

تعداد Timeout

اطلاعات نشست


تمام اطلاعات نمایش‌داده‌شده بر اساس داده‌های واقعی سیستم هستند و هیچ مقدار تخمینی یا ساختگی نمایش داده نمی‌شود.


---

گزارش‌ها

WSR به‌صورت خودکار گزارش‌های کامل را در قالب‌های مختلف تولید می‌کند:

TXT

JSON

HTML

Markdown

CSV


گزارش‌ها شامل مواردی مانند آمار اجرا، اطلاعات جمع‌آوری‌شده، زمان‌بندی عملیات، فایل‌های تولیدشده، تاریخچه دستورات و خلاصه ساختاریافته نتایج هستند.


---

معماری پروژه

این پروژه بر اساس اصول مهندسی نرم‌افزار مدرن توسعه یافته است:

معماری ماژولار

Clean Code

SOLID

DRY

Type Hint

Docstring

مدیریت حرفه‌ای Exception

سیستم افزونه‌پذیر

ساختار قابل نگهداری

خوانایی بالا



---

بهینه‌سازی عملکرد

برای دستیابی به سرعت و پایداری بیشتر، WSR از تکنیک‌هایی مانند موارد زیر بهره می‌برد:

asyncio

ThreadPoolExecutor

مدیریت Queue

Connection Pool

Retry Logic

Lazy Loading

مدیریت منابع

زمان‌بندی همزمان پردازش‌ها



---

تجربه کاربری

WSR با الهام از ابزارهای حرفه‌ای محیط لینوکس طراحی شده و هویت بصری مستقل خود را حفظ کرده است.

ویژگی‌های رابط کاربری شامل:

چیدمان واکنش‌گرا

بروزرسانی زنده اطلاعات

قالب‌های رنگی حرفه‌ای

انیمیشن‌های روان

پنل‌های ساختاریافته

نمایش دقیق وضعیت اجرا

حداقل خروجی غیرضروری



---

پیش‌نیازها

Python 3.10 یا بالاتر

Linux

Kali Linux

Debian

Ubuntu

Fedora

Arch Linux

WSL

Termux



---

اهداف پروژه

معماری حرفه‌ای

اجرای پایدار

عملکرد بالا

تجربه کاربری حرفه‌ای در ترمینال

طراحی ماژولار

توسعه‌پذیری آسان

گزارش‌دهی جامع

پیاده‌سازی تمیز

قابلیت نگهداری بلندمدت







🇬🇧 English

Clone the repository

git clone https://github.com/NoobHacker1243/wrs.git

Enter the project directory

cd wrs

Install dependencies

pip install -r requirements.txt

Run WSR

python3 wsr.py


---

🇮🇷 فارسی

کلون کردن مخزن

git clone https://github.com/NoobHacker1243/wrs.git

ورود به پوشه پروژه

cd wrs

نصب وابستگی‌ها

pip install -r requirements.txt

اجرای WSR

python3 wsr.py







---

مجوز

این پروژه برای اهداف آموزشی، پژوهشی و ارزیابی امنیتیِ دارای مجوز ارائه شده است. مسئولیت استفاده از این نرم‌افزار و رعایت قوانین، مقررات و اخذ مجوزهای لازم، بر عهده کاربر است.

---

License




This project is provided for educational, research, and authorized security assessment purposes. Users are responsible for complying with all applicable laws, regulations, and authorization requirements when using the software.
