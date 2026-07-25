#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import random
import signal
import shlex
import shutil
import socket
import subprocess
import sys
import time
import json
import logging
import argparse
import concurrent.futures
import threading
import uuid
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

__version__ = "1.00"
__author__ = "WSR Team"
__license__ = "MIT"

# ====================== LANGUAGE SYSTEM ======================
_current_lang = "fa"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "fa": {
        "select_language": "زبان را انتخاب کنید",
        "lang_fa": "فارسی",
        "lang_en": "English",
        "scan_level": "سطح اسکن",
        "level_slow": "کند - پایه (اسکن‌های پایه)",
        "level_medium": "متوسط - شماره‌گیری دایرکتوری و ساب‌دامنه",
        "level_strong": "قوی - تست نفوذ کامل",
        "select_level": "انتخاب (1/2/3): ",
        "target_prompt": "آدرس هدف یا مسیر فایل targets.txt: ",
        "no_targets": "هیچ هدفی مشخص نشد",
        "targets_loaded": "تعداد اهداف بارگذاری شده",
        "from_file": "از فایل",
        "selected_level": "سطح انتخاب شده",
        "targets_count": "تعداد اهداف",
        "skipping_tools": "رد شدن از نصب ابزارها",
        "installing_tools": "بررسی و نصب ابزارها",
        "tool_summary": "خلاصه نصب ابزارها",
        "installed_count": "نصب شده",
        "missing_tools": "ابزارهای مفقود",
        "start_scan": "شروع اسکن",
        "target_label": "هدف",
        "domain_label": "دامنه",
        "level_label": "سطح",
        "output_label": "خروجی",
        "start_label": "شروع",
        "running": "در حال اجرای",
        "output_saved": "خروجی ذخیره شد",
        "completed_warnings": "با هشدار تمام شد",
        "timed_out": "منقضی شد",
        "tool_not_found": "ابزار یافت نشد",
        "download_wordlist": "دانلود وردلیست",
        "wordlist_downloaded": "وردلیست دانلود شد",
        "download_failed": "دانلود ناموفق",
        "download_timeout": "دانلود وردلیست منقضی شد",
        "wordlist_exists": "وردلیست از قبل وجود دارد",
        "slow_tests_start": "شروع تست‌های سطح Slow",
        "medium_tests_start": "شروع تست‌های سطح Medium",
        "strong_tests_start": "شروع تست‌های سطح Strong",
        "sqlmap_warning": "اجرای SQLMap...",
        "report_saved": "گزارش ذخیره شد",
        "final_results": "نتیجه نهایی",
        "targets_scanned": "تعداد اهداف اسکن شده",
        "total_duration": "مدت زمان کل",
        "total_scans": "تعداد کل اسکن‌ها",
        "successful": "موفق",
        "failed": "ناموفق",
        "all_complete": "تمام اسکن‌ها و تست‌های امنیتی با موفقیت به پایان رسید",
        "summary_at": "خلاصه کلی در",
        "interrupted": "اسکن توسط کاربر متوقف شد",
        "auto_installing": "در حال نصب خودکار",
        "install_cancelled": "نصب لغو شد",
        "installing": "در حال نصب",
        "installed": "نصب شد",
        "install_failed": "نصب ناموفق بود",
        "install_timeout": "نصب منقضی شد",
        "install_error": "خطا در نصب",
        "apt_not_found": "یافت نشد. آیا اجازه نصب آن را می‌دهید؟ (y/n): ",
        "go_not_found": "آیا اجازه نصب از طریق Go را می‌دهید؟ (y/n): ",
        "go_tool_not_registry": "ابزار در Go یافت نشد",
        "go_installing": "در حال نصب از طریق Go",
        "report_title": "گزارش جامع نهایی WSR",
        "output_files": "فایل‌های خروجی",
        "recommendations": "پیشنهادها",
        "rec_1": "تمام فایل‌های خروجی را به ترتیب اولویت بررسی کنید.",
        "rec_2": "یافته‌های مهم را با Burp Suite یا ZAP تست دستی کنید.",
        "rec_3": "باگ‌های معتبر را گزارش دهید.",
        "rec_4": "نتایج را در مکانی امن نگهداری کنید.",
        "rec_5": "تمام ساب‌دامنه‌ها و اندپوینت‌ها را مرور کنید.",
        "rec_6": "پارامترهای پیدا شده را تست کنید.",
        "multi_target_summary": "خلاصه کلی تمام اهداف WSR",
        "total_targets": "تعداد کل اهداف",
        "grand_total": "مجموع کل",
        "overall_rate": "نرخ موفقیت کل",
        "target_info": "اطلاعات هدف",
        "resolved_ip": "آدرس IP تحلیل شده",
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "reverse_dns": "DNS معکوس",
        "asn": "ASN",
        "isp": "ارائه‌دهنده اینترنت",
        "organization": "سازمان",
        "country": "کشور",
        "city": "شهر",
        "region": "منطقه",
        "hosting_provider": "ارائه‌دهنده هاستینگ",
        "cdn_detection": "تشخیص CDN",
        "waf_detection": "تشخیص WAF",
        "unknown": "نامشخص",
        "gathering_info": "جمع‌آوری اطلاعات هدف",
        "cache_exists": "فایل کش وجود دارد",
        "timeout_label": "تایم‌اوت",
        "success_label": "موفقیت",
        "error_label": "خطا",
        "warning_label": "هشدار",
        "retry_label": "تلاش مجدد",
        "session_id": "شناسه نشست",
        "version_label": "نسخه",
        "pid_label": "شناسه فرآیند",
        "elapsed_time": "زمان سپری شده",
        "current_tool": "ابزار فعلی",
        "next_tool": "ابزار بعدی",
        "completed_tools": "ابزارهای تکمیل شده",
        "remaining_tools": "ابزارهای باقی‌مانده",
        "progress_label": "پیشرفت",
        "eta_label": "زمان باقی‌مانده",
        "cpu_label": "پردازنده",
        "ram_label": "حافظه",
        "disk_label": "دیسک",
        "network_label": "شبکه",
        "thread_label": "رشته",
        "queue_label": "صف",
        "output_size": "اندازه خروجی",
        "log_size": "اندازه لاگ",
    },
    "en": {
        "select_language": "Select Language",
        "lang_fa": "فارسی",
        "lang_en": "English",
        "scan_level": "Scan Level",
        "level_slow": "Slow - Basic (Basic scans)",
        "level_medium": "Medium - Directory & subdomain enumeration",
        "level_strong": "Strong - Full penetration testing suite",
        "select_level": "Select (1/2/3): ",
        "target_prompt": "Target URL or path to targets.txt: ",
        "no_targets": "No targets specified",
        "targets_loaded": "Targets loaded",
        "from_file": "from file",
        "selected_level": "Selected level",
        "targets_count": "Targets count",
        "skipping_tools": "Skipping tool installation",
        "installing_tools": "Checking & Installing Tools",
        "tool_summary": "Tool Installation Summary",
        "installed_count": "Installed",
        "missing_tools": "Missing tools",
        "start_scan": "Start Scan",
        "target_label": "Target",
        "domain_label": "Domain",
        "level_label": "Level",
        "output_label": "Output",
        "start_label": "Start",
        "running": "Running",
        "output_saved": "Output saved",
        "completed_warnings": "Completed with warnings",
        "timed_out": "Timed out",
        "tool_not_found": "Tool not found",
        "download_wordlist": "Downloading wordlist",
        "wordlist_downloaded": "Wordlist downloaded",
        "download_failed": "Download failed",
        "download_timeout": "Wordlist download timed out",
        "wordlist_exists": "Wordlist already exists",
        "slow_tests_start": "Starting Slow Level Tests",
        "medium_tests_start": "Starting Medium Level Tests",
        "strong_tests_start": "Starting Strong Level Tests",
        "sqlmap_warning": "Running SQLMap...",
        "report_saved": "Report saved",
        "final_results": "Final Results",
        "targets_scanned": "Targets Scanned",
        "total_duration": "Total Duration",
        "total_scans": "Total Scans",
        "successful": "Successful",
        "failed": "Failed",
        "all_complete": "All scans and security tests completed successfully",
        "summary_at": "Summary at",
        "interrupted": "Scan interrupted by user",
        "auto_installing": "Auto-installing",
        "install_cancelled": "Installation cancelled",
        "installing": "Installing",
        "installed": "installed",
        "install_failed": "Installation failed",
        "install_timeout": "Installation timed out",
        "install_error": "Error installing",
        "apt_not_found": "not found. Allow installation? (y/n): ",
        "go_not_found": "Allow installation via Go? (y/n): ",
        "go_tool_not_registry": "Go tool not in registry",
        "go_installing": "Installing via Go",
        "report_title": "WSR Final Detailed Report",
        "output_files": "Output Files",
        "recommendations": "Recommendations",
        "rec_1": "Review all output files in priority order.",
        "rec_2": "Manually test important findings with Burp Suite or ZAP.",
        "rec_3": "Report valid bugs.",
        "rec_4": "Store results in a secure location.",
        "rec_5": "Review all subdomains and endpoints.",
        "rec_6": "Test discovered parameters.",
        "multi_target_summary": "WSR Multi-Target Summary",
        "total_targets": "Total Targets",
        "grand_total": "Grand Total",
        "overall_rate": "Overall Success Rate",
        "target_info": "Target Information",
        "resolved_ip": "Resolved IP",
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "reverse_dns": "Reverse DNS",
        "asn": "ASN",
        "isp": "ISP",
        "organization": "Organization",
        "country": "Country",
        "city": "City",
        "region": "Region",
        "hosting_provider": "Hosting Provider",
        "cdn_detection": "CDN Detection",
        "waf_detection": "WAF Detection",
        "unknown": "Unknown",
        "gathering_info": "Gathering target information",
        "cache_exists": "Cache file exists",
        "timeout_label": "Timeout",
        "success_label": "Success",
        "error_label": "Error",
        "warning_label": "Warning",
        "retry_label": "Retry",
        "session_id": "Session ID",
        "version_label": "Version",
        "pid_label": "PID",
        "elapsed_time": "Elapsed Time",
        "current_tool": "Current Tool",
        "next_tool": "Next Tool",
        "completed_tools": "Completed Tools",
        "remaining_tools": "Remaining Tools",
        "progress_label": "Progress",
        "eta_label": "ETA",
        "cpu_label": "CPU",
        "ram_label": "RAM",
        "disk_label": "Disk",
        "network_label": "Network",
        "thread_label": "Thread",
        "queue_label": "Queue",
        "output_size": "Output Size",
        "log_size": "Log Size",
    },
}


def t(key: str) -> str:
    lang_dict = TRANSLATIONS.get(_current_lang, TRANSLATIONS["fa"])
    return lang_dict.get(key, TRANSLATIONS["fa"].get(key, key))


def set_language(lang: str) -> None:
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang


def get_language() -> str:
    return _current_lang


# ====================== بنرها ======================
BANNERS = [
    """\033[95m
╔════════════════════════════════════════════════════════════════════╗
║                    WSR - WEB SECURITY RECON                        ║
║                       امپراتوری هخامنشی                          ║
╚════════════════════════════════════════════════════════════════════╝\033[0m""",

    """\033[93m
╔════════════════════════════════════════════════════════════════════╗
║                    WSR - WEB SECURITY RECON                        ║
║                        شیر و خورشید                               ║
╚════════════════════════════════════════════════════════════════════╝\033[0m""",

    """\033[96m
╔════════════════════════════════════════════════════════════════════╗
║                    WSR - WEB SECURITY RECON                        ║
║                       امپراتوری ساسانی                           ║
╚════════════════════════════════════════════════════════════════════╝\033[0m""",

    """\033[92m
╔════════════════════════════════════════════════════════════════════╗
║                    WSR - WEB SECURITY RECON                        ║
║                     ایران باستان تا امروز                        ║
╚════════════════════════════════════════════════════════════════════╝\033[0m"""
]

ASCII_BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡐⣐⡂⡢⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡒⡖⡖⠤⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡨⡅⠕⢱⢩⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠡⠧⢍⠢⡒⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⢠⠢⢕⠣⠉⡄⣓⢌⠪⡂⠙⡌⠖⡄⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢔⢕⢪⠒⠉⠐⢆⢐⠔⠔⢝⢎⠆⠀⠀⠁⠈⢔⠣⡢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢔⢕⠅⠁⢸⠀⠀⠀⡈⢄⠎⢊⠠⠑⠝⠄⠀⠀⠀⠀⠈⠪⠪⣂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡪⠡⠂⠀⠀⠀⠉⠒⠉⢀⠠⡈⠤⠩⡡⠡⡁⠀⠀⠀⠀⠀⠀⠐⡑⣑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢌⠢⠁⠀⠀⠀⠀⠀⠀⢀⠰⡑⡐⡁⡑⡐⠱⣐⠀⠀⠀⠀⠀⠀⠀⠈⡰⡡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠁⡁⠀⠀⠀⠀⠀⠀⢀⠎⠂⠄⢂⠀⠂⠄⡁⢐⠱⡀⠀⠀⠀⠀⠀⠀⠐⢑⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠩⢙⢑⢒⠒⠴⠐⠦⠢⢤⢤⠤⡀⢄⢀⣀⣀⣀⣀⡀⣀⣀⣀⣀⣀⣠⣁⣂⣀⣀⣀⣀⠀⠀⡌⡂⠁⠠⠐⠀⢂⠀⡀⠐⠨⢢⠀⢀⣀⣀⣀⣀⣨⣀⣅⣀⣀⣀⣀⣀⢀⣀⣀⣀⡀⡀⡄⢄⢤⢤⠤⠔⠴⠰⢔⢐⠒⢍⠣⠉⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠂⠂⡒⡘⢌⢂⠊⠊⠂⠢⠡⠠⠐⢐⠐⢐⢐⣐⢀⢒⢐⢐⠐⢐⠠⢐⢠⢀⠠⠰⡀⠀⢨⢈⠄⠐⠐⠈⠈⠀⠂⠂⠅⡂⠅⡃⠀⡐⠄⠄⢠⠠⡀⣂⠂⢐⢐⢐⠂⡂⣂⡂⡂⠂⠂⠂⠔⠐⠄⠕⠕⠂⢌⢒⢒⠐⡐⠨⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠨⠈⠢⠈⠢⢑⠈⢨⡨⡈⡨⠌⢌⠈⠬⢀⢒⠐⠄⢄⠐⠠⢑⠄⡢⠡⡑⡐⡡⠁⡂⢅⠆⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢌⠠⢈⠈⠌⡂⠅⢄⢄⠊⠄⠂⠄⡄⠢⢂⡒⠌⠌⠡⠩⠱⠡⡁⣡⡑⠈⡂⠅⠅⠑⠌⡐⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢈⠠⡁⡁⣁⠁⢆⠈⠢⢐⢂⢁⠅⢅⢀⠂⠊⠌⡂⢅⠊⠔⠠⢈⠌⢄⠠⠨⠠⢀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠡⠀⠌⠄⠌⠌⢄⠡⠨⡈⠪⡈⠪⠨⠂⡈⢌⠨⠨⢌⡂⡃⠢⠂⠤⡁⣁⢁⠡⡈⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⡀⠢⠅⡂⠢⡁⢄⠂⠂⡊⠔⡐⠕⡐⠔⡀⡂⠅⠌⢌⠄⡨⠠⢁⠅⠅⡐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠅⠡⢁⠡⡈⢄⢅⠡⡀⢅⠢⡐⠄⡑⢌⢢⠡⢑⠐⠀⢌⢈⠂⢂⠢⡐⡀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⠂⠑⠌⠔⠄⡑⠄⢅⠠⠪⠨⠠⡠⡈⠄⠅⠄⡠⠠⠁⠄⣈⢠⠠⢃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠌⠢⠨⣀⠡⠈⠄⠄⠐⠌⢄⠨⠀⠅⠄⠅⢔⠈⠢⡈⠌⠢⠠⠉⠐⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠈⠀⠀⠁⠈⠔⢀⠐⠌⠌⢂⠀⠡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠌⠀⡂⠅⡓⢌⢀⠡⡈⠀⠁⠈⠀⠁⠁⠀⠁⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠌⡐⠅⠅⠂⠁⠄⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠠⠀⠅⠠⠀⢣⠐⡐⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⢄⠀⠌⠄⠌⠀⠂⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠐⠀⠱⡀⠑⡀⠠⠤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠡⠠⠪⠈⡨⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠄⢢⠁⠨⠠⡑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡐⠠⠀⠀⠄⠂⠂⡂⠂⢂⠂⢂⠂⠂⡂⢂⠂⢂⠂⡂⢂⠂⢂⠂⢂⠂⡂⠂⡂⠂⠢⠀⠐⠠⠀⠡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡐⠠⠀⢀⠀⠀⠌⠀⠄⢈⠠⠐⠀⠄⠁⠄⠠⠐⠀⠄⠠⠀⠂⡀⠂⡀⠂⡀⠂⡀⢁⠨⠀⠀⠠⠈⡀⡣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡐⠄⠂⠂⠀⠀⠀⠁⠀⠂⠀⠄⠂⠁⡀⠁⠐⠀⡈⠀⠂⠐⠀⢁⠀⠂⠀⠂⡀⠄⠠⠀⡀⠀⠀⠀⠀⠠⠨⢐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⡂⠄⢄⠀⠀⠄⠁⠀⠂⠀⠄⠁⠀⠀⠁⡀⠠⠀⠁⠀⠁⠀⡀⠈⠀⠁⢀⠠⠀⠠⠐⠀⢀⠠⢐⠀⡂⢀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠂⠨⠐⠀⠅⠅⠀⠀⠐⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠁⠀⠁⠀⠀⠁⠀⡀⠀⡀⠄⢈⠈⠂⠌⠀⠂⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠐⠀⠈⢀⠀⠀⠀⠀⠀⠈⠀⠀⠈⠀⠀⠀⠁⠀⠀⠀⠀⠀⠂⠁⠀⠀⠀⠀⡂⠀⠈⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

VERSION_INFO = r"""
\033[96m
  ██╗    ██╗███████╗██████╗     ███████╗████████╗██╗   ██╗██████╗ ██╗ ██████╗
  ██║    ██║██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██║   ██║██╔══██╗██║██╔═══██╗
  ██║ █╗ ██║█████╗  ██████╔╝    ███████╗   ██║   ██║   ██║██████╔╝██║██║   ██║
  ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║   ██║   ██║   ██║██╔══██╗██║██║   ██║
  ╚███╔███╔╝███████╗██████╔╝    ███████║   ██║   ╚██████╔╝██║  ██║██║╚██████╔╝
   ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝
\033[0m\033[93m  Web Security Recon Tool v1.00 | Iranian Bug Bounty Platform\033[0m
"""

# ====================== COLORS ======================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[97m'
    MAGENTA = '\033[35m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    GRAY = '\033[90m'
    ORANGE = '\033[38;5;208m'


def supports_color() -> bool:
    if os.getenv("WSR_NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


_COLOR_ENABLED = True


def enable_color(enabled: bool = True) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def c(text: str, color: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"{color}{text}{Colors.ENDC}"


def cprint(text: str, color: str, **kwargs) -> None:
    print(c(text, color), **kwargs)


# ====================== CONFIG ======================
TIMEOUTS: Dict[str, int] = {
    'slow': 180,
    'medium': 300,
    'strong': 600,
}

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
BIG_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt"

GO_TOOLS: Dict[str, str] = {
    'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'amass': 'github.com/owasp-amass/amass/v4/cmd/amass@latest',
    'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
    'katana': 'github.com/projectdiscovery/katana/cmd/katana@latest',
    'gau': 'github.com/lc/gau/v2/cmd/gau@latest',
    'waybackurls': 'github.com/tomnomnom/waybackurls@latest',
    'arjun': 'github.com/s0md3v/Arjun@master',
    'dalfox': 'github.com/hahwul/dalfox/v2@latest',
    'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    'dnsx': 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    'wafw00f': 'github.com/EnableSecurity/wafw00f@master',
}

APT_PACKAGES: List[str] = [
    'nmap', 'nikto', 'whatweb', 'sqlmap', 'gobuster',
    'ffuf', 'wget', 'sslscan', 'gowitness',
]


@dataclass
class ScanConfig:
    level: Optional[str] = None
    targets_file: Optional[str] = None
    target_url: Optional[str] = None
    output_dir: str = "scans"
    scan_delay_min: int = 3
    scan_delay_max: int = 10
    max_threads: int = 10
    parallel_scans: bool = False
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    skip_install: bool = False
    auto_install: bool = False
    config_file: Optional[str] = None
    report_format: str = "text"
    language: Optional[str] = None
    extra_args: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        config_path = Path(path).resolve()
        if not config_path.exists():
            return cls()
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)

    def save(self, path: str) -> None:
        config_path = Path(path).resolve()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for f_name, f_obj in self.__dataclass_fields__.items():
            data[f_name] = getattr(self, f_name)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_timeout(self) -> int:
        return TIMEOUTS.get(self.level, 300)

    def get_scan_dir(self, domain: str, timestamp: str) -> Path:
        base = Path(self.output_dir).resolve()
        return base / f"{domain}_{timestamp}"

    def get_wordlist_url(self) -> str:
        return WORDLIST_URL

    def get_big_wordlist_url(self) -> str:
        return BIG_WORDLIST_URL

    def get_wordlist_path(self, scan_dir: Path) -> Path:
        return Path("/usr/share/wordlists/dirb/common.txt")

    def get_big_wordlist_path(self, scan_dir: Path) -> Path:
        return Path("/usr/share/wordlists/big.txt")

    def get_nuclei_templates_path(self) -> str:
        return os.path.expanduser("~/nuclei-templates")

    def get_gopath_bin(self) -> Path:
        return Path.home() / "go" / "bin"


# ====================== UTILS ======================
def sanitize_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return re.sub(r'[^a-zA-Z0-9.-]', '_', domain)


def validate_url(url: str) -> Tuple[str, urlparse]:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"آدرس نامعتبر | Invalid URL: {url}")
    return url, parsed


def create_scan_directory(base_dir: str, domain: str) -> Tuple[Path, str]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = Path(base_dir).resolve() / f"{domain}_{timestamp}"
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir, timestamp


def format_duration(duration) -> str:
    total_seconds = int(duration.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def safe_file_read(path: str) -> Optional[str]:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_size_kb(path: str) -> float:
    try:
        return os.path.getsize(path) / 1024
    except OSError:
        return 0.0


# ====================== SESSION MANAGER ======================
class SessionManager:
    _instance: Optional["SessionManager"] = None

    def __init__(self) -> None:
        self.session_id: str = str(uuid.uuid4())[:8].upper()
        self.start_time: datetime = datetime.now()
        self.pid: int = os.getpid()
        self._history: List[Dict[str, Any]] = []
        self._history_file: str = str(Path.home() / ".wsr" / "history.json")
        self._load_history()

    @classmethod
    def get_instance(cls) -> "SessionManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    def _load_history(self) -> None:
        try:
            hpath = Path(self._history_file)
            if hpath.exists():
                with open(str(hpath), 'r', encoding='utf-8') as f:
                    self._history = json.load(f)
        except Exception:
            self._history = []

    def _save_history(self) -> None:
        try:
            hpath = Path(self._history_file)
            hpath.parent.mkdir(parents=True, exist_ok=True)
            with open(str(hpath), 'w', encoding='utf-8') as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def add_history(self, target: str, level: str, scan_dir: str, stats: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "session_id": self.session_id,
            "target": target,
            "level": level,
            "scan_dir": scan_dir,
            "timestamp": datetime.now().isoformat(),
            "stats": stats,
        }
        self._history.append(entry)
        self._save_history()

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._history[-limit:]

    def get_elapsed(self) -> str:
        return format_duration(datetime.now() - self.start_time)


# ====================== SESSION RESUME ======================
class ResumeManager:
    def __init__(self, scan_dir: str) -> None:
        self.state_file = str(Path(scan_dir) / ".wsr_state.json")
        self._state: Dict[str, Any] = {"completed_steps": [], "level": "", "target": ""}

    def load(self) -> Dict[str, Any]:
        try:
            if Path(self.state_file).exists():
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    self._state = json.load(f)
        except Exception:
            self._state = {"completed_steps": [], "level": "", "target": ""}
        return self._state

    def save(self) -> None:
        try:
            Path(self.state_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def mark_completed(self, step: str) -> None:
        if step not in self._state["completed_steps"]:
            self._state["completed_steps"].append(step)
            self.save()

    def is_completed(self, step: str) -> bool:
        return step in self._state["completed_steps"]

    def set_target(self, target: str) -> None:
        self._state["target"] = target
        self.save()

    def set_level(self, level: str) -> None:
        self._state["level"] = level
        self.save()


# ====================== TARGET INFO ======================
class TargetInfoGatherer:
    def __init__(self, logger: Optional["WSRLogger"] = None):
        self.logger = logger or WSRLogger.get_instance()

    def gather(self, url: str, domain: str) -> Dict[str, str]:
        info: Dict[str, str] = {}
        info[t("target_label")] = url
        info[t("domain_label")] = domain
        info[t("resolved_ip")] = self._get_ip(domain)
        info[t("ipv4")] = self._get_ipv4(domain)
        info[t("ipv6")] = self._get_ipv6(domain)
        info[t("reverse_dns")] = self._get_reverse_dns(domain)
        info[t("asn")] = self._get_asn(domain)
        info[t("isp")] = self._get_isp(domain)
        info[t("organization")] = self._get_org(domain)
        info[t("country")] = self._get_country(domain)
        info[t("city")] = self._get_city(domain)
        info[t("region")] = self._get_region(domain)
        info[t("hosting_provider")] = self._get_hosting(domain)
        info[t("cdn_detection")] = self._detect_cdn(url)
        info[t("waf_detection")] = self._detect_waf(url)
        return info

    def display(self, info: Dict[str, str]) -> None:
        self.logger.section(t("target_info"))
        for key, value in info.items():
            color = Colors.CYAN
            if key in (t("target_label"), t("domain_label")):
                color = Colors.GREEN
            elif key in (t("resolved_ip"), t("ipv4"), t("ipv6")):
                color = Colors.YELLOW
            elif key in (t("cdn_detection"), t("waf_detection")):
                color = Colors.RED if value != t("unknown") and value != "N/A" else Colors.GRAY
            self.logger.table_row(key, value, color)

    def _get_ip(self, domain: str) -> str:
        try:
            ips = socket.getaddrinfo(domain, None)
            if ips:
                return ips[0][4][0]
        except Exception:
            pass
        return t("unknown")

    def _get_ipv4(self, domain: str) -> str:
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            if result:
                return result[0][4][0]
        except Exception:
            pass
        return t("unknown")

    def _get_ipv6(self, domain: str) -> str:
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET6)
            if result:
                return result[0][4][0]
        except Exception:
            pass
        return t("unknown")

    def _get_reverse_dns(self, domain: str) -> str:
        try:
            ip = self._get_ip(domain)
            if ip == t("unknown"):
                return t("unknown")
            hostname = socket.gethostbyaddr(ip)
            if hostname:
                return hostname[0]
        except Exception:
            pass
        return t("unknown")

    def _run_cmd_safe(self, cmd: List[str], timeout: int = 10) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except Exception:
            return ""

    def _get_asn(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            if "originas" in line.lower() or "asnumber" in line.lower() or line.strip().startswith("AS"):
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val:
                    return val
        return t("unknown")

    def _get_isp(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            lower = line.lower()
            if "netname" in lower or "org-name" in lower or "descr" in lower:
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val and val.lower() not in ("netname", "descr", "org-name", "null"):
                    return val
        return t("unknown")

    def _get_org(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            lower = line.lower()
            if "org-name" in lower or "organization" in lower or "orgname" in lower:
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val:
                    return val
        return t("unknown")

    def _get_country(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            if "country" in line.lower():
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val and len(val) <= 4:
                    return val
        return t("unknown")

    def _get_city(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            if "city" in line.lower():
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val:
                    return val
        return t("unknown")

    def _get_region(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        for line in output.split("\n"):
            if "stateprov" in line.lower() or "region" in line.lower():
                val = line.split(":")[-1].strip() if ":" in line else line.strip()
                if val:
                    return val
        return t("unknown")

    def _get_hosting(self, domain: str) -> str:
        ip = self._get_ip(domain)
        if ip == t("unknown"):
            return t("unknown")
        output = self._run_cmd_safe(["whois", ip])
        hosting_keywords = ["cloudflare", "amazon", "aws", "google", "azure", "digitalocean",
                            "linode", "vultr", "hetzner", "ovh", "kinsta", "siteground"]
        for line in output.split("\n"):
            lower = line.lower()
            for kw in hosting_keywords:
                if kw in lower:
                    return line.split(":")[-1].strip() if ":" in line else kw
        return t("unknown")

    def _detect_cdn(self, url: str) -> str:
        output = self._run_cmd_safe(["curl", "-sI", "-m", "10", url])
        cdn_headers = {
            "cf-ray": "Cloudflare",
            "x-cdn": "CDN",
            "x-amz-cf-id": "AWS CloudFront",
            "x-cache": "Cache",
            "via": "Proxy/CDN",
            "x-served-by": "Fastly/Varnish",
        }
        output_lower = output.lower()
        for header, name in cdn_headers.items():
            if header.lower() in output_lower:
                return name
        return t("unknown")

    def _detect_waf(self, url: str) -> str:
        output = self._run_cmd_safe(["curl", "-sI", "-m", "10", url])
        waf_signatures = {
            "x-sucuri-id": "Sucuri WAF",
            "x-cdn-by": "CDN WAF",
            "server: cloudflare": "Cloudflare WAF",
            "x-akamai": "Akamai WAF",
            "x-waf": "WAF Detected",
            "x-protected-by": "WAF Detected",
        }
        output_lower = output.lower()
        for sig, name in waf_signatures.items():
            if sig.lower() in output_lower:
                return name
        return t("unknown")


# ====================== LOGGING ======================
class WSRLogger:
    _instance: Optional["WSRLogger"] = None

    def __init__(self, log_file: Optional[str] = None, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self._log_file = log_file
        self._logger = logging.getLogger("wsr")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_fmt = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_fmt)
        self._logger.addHandler(console_handler)
        if log_file:
            log_path = Path(log_file).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                "[%(asctime)s] %(levelname)-8s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_fmt)
            self._logger.addHandler(file_handler)
        self._raw_file = None
        if log_file:
            raw_path = Path(log_file).with_suffix('.raw.log')
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            self._raw_file = open(str(raw_path), 'a', encoding='utf-8')

    @classmethod
    def get_instance(cls, **kwargs) -> "WSRLogger":
        if cls._instance is None:
            cls._instance = cls(**kwargs)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    def _write_raw(self, text: str) -> None:
        if self._raw_file:
            self._raw_file.write(text + "\n")
            self._raw_file.flush()

    def step(self, msg: str) -> None:
        formatted = f"{Colors.BLUE}[*]{Colors.ENDC} {msg}"
        if not self.quiet:
            print(formatted)
        self._logger.info(f"[*] {msg}")
        self._write_raw(f"[*] {msg}")

    def success(self, msg: str) -> None:
        formatted = f"{Colors.GREEN}[+]{Colors.ENDC} {msg}"
        if not self.quiet:
            print(formatted)
        self._logger.info(f"[+] {msg}")
        self._write_raw(f"[+] {msg}")

    def warning(self, msg: str) -> None:
        formatted = f"{Colors.YELLOW}[!]{Colors.ENDC} {msg}"
        if not self.quiet:
            print(formatted)
        self._logger.warning(f"[!] {msg}")
        self._write_raw(f"[!] {msg}")

    def error(self, msg: str) -> None:
        formatted = f"{Colors.RED}[-]{Colors.ENDC} {msg}"
        if not self.quiet:
            print(formatted)
        self._logger.error(f"[-] {msg}")
        self._write_raw(f"[-] {msg}")

    def debug(self, msg: str) -> None:
        if self.verbose:
            formatted = f"{Colors.GRAY}[D]{Colors.ENDC} {msg}"
            print(formatted)
        self._logger.debug(f"[D] {msg}")
        self._write_raw(f"[D] {msg}")

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(msg)
        self._logger.info(msg)
        self._write_raw(msg)

    def banner(self, text: str) -> None:
        if not self.quiet:
            print(text)
        self._write_raw("[BANNER]")

    def section(self, title: str) -> None:
        separator = "=" * 70
        formatted = f"\n{Colors.BOLD}{Colors.CYAN}{separator}{Colors.ENDC}\n{Colors.BOLD}  {title}{Colors.ENDC}\n{Colors.BOLD}{Colors.CYAN}{separator}{Colors.ENDC}"
        if not self.quiet:
            print(formatted)
        self._logger.info(f"\n{separator}\n  {title}\n{separator}")
        self._write_raw(f"\n{separator}\n  {title}\n{separator}")

    def subsection(self, title: str) -> None:
        separator = "-" * 50
        formatted = f"\n{Colors.YELLOW}{separator}{Colors.ENDC}\n{Colors.BOLD}  {title}{Colors.ENDC}\n{Colors.YELLOW}{separator}{Colors.ENDC}"
        if not self.quiet:
            print(formatted)
        self._logger.info(f"\n{separator}\n  {title}\n{separator}")
        self._write_raw(f"\n{separator}\n  {title}\n{separator}")

    def table_row(self, label: str, value: str, color: str = Colors.WHITE) -> None:
        formatted = f"  {Colors.DIM}│{Colors.ENDC} {label:<35} {Colors.DIM}│{Colors.ENDC} {c(str(value), color)}"
        if not self.quiet:
            print(formatted)
        self._write_raw(f"  | {label:<35} | {value}")

    def progress_bar(self, current: int, total: int, prefix: str = "", suffix: str = "") -> None:
        if self.quiet:
            return
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        percent = current / total * 100
        line = f"\r  {Colors.CYAN}{bar}{Colors.ENDC} {percent:5.1f}% {prefix} {suffix}"
        sys.stdout.write(line)
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def close(self) -> None:
        if self._raw_file:
            self._raw_file.close()
            self._raw_file = None


# ====================== TOOL INSTALLER ======================
class ToolInstaller:
    def __init__(self, logger: Optional[WSRLogger] = None, auto_install: bool = False):
        self.logger = logger or WSRLogger.get_instance()
        self.auto_install = auto_install
        self._installed: Dict[str, bool] = {}
        self._not_installed: List[str] = []

    def check_tool(self, tool: str) -> bool:
        if tool in self._installed:
            return self._installed[tool]
        found = shutil.which(tool) is not None
        go_bin = Path.home() / "go" / "bin" / tool
        if not found and go_bin.exists():
            found = True
            os.environ["PATH"] += os.pathsep + str(Path.home() / "go" / "bin")
        self._installed[tool] = found
        return found

    def install_apt_package(self, package: str) -> bool:
        if self.check_tool(package):
            return True
        if self.auto_install:
            self.logger.warning(f"{t('auto_installing')} {package}...")
        else:
            try:
                response = input(
                    f"{package} {t('apt_not_found')}"
                ).strip().lower()
            except EOFError:
                response = 'n'
            if response not in ['y', 'yes', 'بله']:
                self.logger.error(f"{t('install_cancelled')}: {package}")
                self._not_installed.append(package)
                return False
            self.logger.warning(f"{t('installing')} {package}...")
        try:
            result = subprocess.run(
                ['sudo', 'apt', 'install', '-y', package],
                capture_output=True, text=True, timeout=120
            )
            if shutil.which(package):
                self.logger.success(f"{package} {t('installed')}")
                self._installed[package] = True
                return True
            self.logger.error(f"{package} {t('install_failed')}")
            self._not_installed.append(package)
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"{package} {t('install_timeout')}")
            self._not_installed.append(package)
            return False
        except Exception as e:
            self.logger.error(f"{t('install_error')} {package}: {e}")
            self._not_installed.append(package)
            return False

    def install_go_tool(self, tool: str) -> bool:
        if self.check_tool(tool):
            return True
        if tool not in GO_TOOLS:
            self.logger.warning(f"{t('go_tool_not_registry')}: {tool}")
            return False
        if self.auto_install:
            self.logger.warning(f"{t('auto_installing')} {tool} ({t('go_installing')})...")
        else:
            try:
                response = input(
                    f"{t('go_not_found')}"
                ).strip().lower()
            except EOFError:
                response = 'n'
            if response not in ['y', 'yes', 'بله']:
                self.logger.error(f"{t('install_cancelled')}: {tool}")
                self._not_installed.append(tool)
                return False
            self.logger.warning(f"{t('installing')} {tool}...")
        try:
            result = subprocess.run(
                ['go', 'install', '-v', GO_TOOLS[tool]],
                capture_output=True, text=True, timeout=600
            )
            go_bin = Path.home() / "go" / "bin" / tool
            if shutil.which(tool) or go_bin.exists():
                os.environ["PATH"] += os.pathsep + str(Path.home() / "go" / "bin")
                self.logger.success(f"{tool} {t('installed')}")
                self._installed[tool] = True
                return True
            self.logger.error(f"{tool} {t('install_failed')}")
            self._not_installed.append(tool)
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"{tool} {t('install_timeout')}")
            self._not_installed.append(tool)
            return False
        except Exception as e:
            self.logger.error(f"{t('install_error')} {tool}: {e}")
            self._not_installed.append(tool)
            return False

    def install_all_apt(self) -> Dict[str, bool]:
        results = {}
        for pkg in APT_PACKAGES:
            results[pkg] = self.install_apt_package(pkg)
        return results

    def install_all_go(self) -> Dict[str, bool]:
        results = {}
        for tool in GO_TOOLS:
            results[tool] = self.install_go_tool(tool)
        return results

    def install_all(self) -> Dict[str, bool]:
        results = {}
        results.update(self.install_all_apt())
        results.update(self.install_all_go())
        return results

    def get_missing_tools(self) -> List[str]:
        missing = []
        for pkg in APT_PACKAGES:
            if not self.check_tool(pkg):
                missing.append(pkg)
        for tool in GO_TOOLS:
            if not self.check_tool(tool):
                missing.append(tool)
        return missing

    def get_installed_count(self) -> int:
        count = 0
        for pkg in APT_PACKAGES:
            if self.check_tool(pkg):
                count += 1
        for tool in GO_TOOLS:
            if self.check_tool(tool):
                count += 1
        return count

    def get_total_count(self) -> int:
        return len(APT_PACKAGES) + len(GO_TOOLS)

    def print_summary(self) -> None:
        self.logger.section(t("tool_summary"))
        installed = self.get_installed_count()
        total = self.get_total_count()
        self.logger.table_row(t("installed_count"), f"{installed}/{total}")
        if self._not_installed:
            self.logger.warning(f"{t('missing_tools')}: {', '.join(self._not_installed)}")


# ====================== EXECUTOR ======================
class ScanStatistics:
    def __init__(self) -> None:
        self.total: int = 0
        self.success: int = 0
        self.failed: int = 0
        self.files: Dict[str, str] = {}
        self.start_time: datetime = datetime.now()

    def reset(self) -> None:
        self.total = 0
        self.success = 0
        self.failed = 0
        self.files = {}
        self.start_time = datetime.now()

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.success / self.total) * 100

    def summary_dict(self) -> Dict[str, Any]:
        return {
            'total': self.total,
            'success': self.success,
            'failed': self.failed,
            'success_rate': f"{self.success_rate:.1f}%",
            'files': dict(self.files),
        }


class CommandExecutor:
    def __init__(self, logger: Optional[WSRLogger] = None, timeout: int = 300):
        self.logger = logger or WSRLogger.get_instance()
        self.timeout = timeout
        self.stats = ScanStatistics()

    def reset_stats(self) -> None:
        self.stats.reset()

    def run(
        self,
        cmd_list: List[str],
        output_file: Optional[str] = None,
        description: str = "",
        timeout: Optional[int] = None,
        shell: bool = False,
    ) -> str:
        self.stats.total += 1
        self.logger.step(f"{t('running')}: {description}")
        self.logger.debug(f"Command: {' '.join(map(str, cmd_list))}")

        actual_timeout = timeout or self.timeout

        try:
            if shell and isinstance(cmd_list, list):
                cmd_str = " ".join(map(str, cmd_list))
                result = subprocess.run(
                    cmd_str, shell=True, capture_output=True,
                    text=True, timeout=actual_timeout
                )
            else:
                result = subprocess.run(
                    cmd_list, capture_output=True, text=True,
                    timeout=actual_timeout
                )

            output = result.stdout + result.stderr

            if output_file:
                self._write_output(output_file, description, output)

            if result.returncode == 0:
                self.stats.success += 1
                self.logger.success(f"{description} - {t('output_saved')}")
            else:
                self.stats.failed += 1
                self.logger.warning(f"{description} - {t('completed_warnings')}")
            return output

        except subprocess.TimeoutExpired:
            self.stats.failed += 1
            self.logger.error(f"{description} - {t('timed_out')} ({actual_timeout}s)")
            return ""
        except FileNotFoundError:
            self.stats.failed += 1
            self.logger.error(f"{description} - {t('tool_not_found')}: {cmd_list[0]}")
            return ""
        except Exception as e:
            self.stats.failed += 1
            self.logger.error(f"{description}: {str(e)}")
            return str(e)

    def run_with_delay(
        self,
        cmd_list: List[str],
        output_file: Optional[str] = None,
        description: str = "",
        timeout: Optional[int] = None,
        delay_min: int = 3,
        delay_max: int = 10,
        shell: bool = False,
    ) -> str:
        result = self.run(cmd_list, output_file, description, timeout, shell)
        delay = random.randint(delay_min, delay_max)
        self.logger.debug(f"Waiting {delay}s before next scan...")
        time.sleep(delay)
        return result

    def run_parallel(
        self,
        commands: List[Dict[str, Any]],
        delay_min: int = 3,
        delay_max: int = 10,
    ) -> Dict[str, str]:
        results: Dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(commands), 5)) as executor:
            future_map = {}
            for cmd_info in commands:
                future = executor.submit(
                    self.run,
                    cmd_info['cmd'],
                    cmd_info.get('output_file'),
                    cmd_info.get('description', ''),
                    cmd_info.get('timeout'),
                    cmd_info.get('shell', False),
                )
                future_map[future] = cmd_info.get('description', 'unknown')
            for future in concurrent.futures.as_completed(future_map):
                desc = future_map[future]
                try:
                    results[desc] = future.result()
                except Exception as e:
                    results[desc] = str(e)
        return results

    def _write_output(self, output_file: str, description: str, output: str) -> None:
        output_path = Path(output_file).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a', encoding='utf-8') as f:
            header = f"\n{'='*90}\n{description} - {datetime.now()}\n{'='*90}\n"
            f.write(header)
            f.write(output)
            f.write("\n")
        self.stats.files[description] = str(output_path)

    def download_wordlist(self, url: str, dest_path: str) -> bool:
        dest = Path(dest_path).resolve()
        if dest.exists() and dest.stat().st_size > 5000:
            self.logger.debug(f"{t('wordlist_exists')}: {dest.name}")
            return True
        self.logger.warning(f"{t('download_wordlist')}: {dest.name}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ['wget', '-q', '-O', str(dest), url],
                check=True, timeout=120
            )
            self.logger.success(t("wordlist_downloaded"))
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(t("download_timeout"))
            return False
        except Exception as e:
            self.logger.error(f"{t('download_failed')}: {str(e)}")
            return False


# ====================== REPORT GENERATOR ======================
class ReportGenerator:
    def __init__(self, logger: Optional[WSRLogger] = None):
        self.logger = logger or WSRLogger.get_instance()

    def generate_target_report(
        self,
        url: str,
        domain: str,
        level: str,
        start_time: datetime,
        scan_dir: Path,
        stats: ScanStatistics,
        report_file: str,
    ) -> None:
        duration = datetime.now() - start_time
        report_path = Path(report_file).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        lines.append(f"{'='*90}")
        lines.append(f"  WSR v1.00 - {t('report_title')}")
        lines.append(f"{'='*90}")
        lines.append(f"")
        lines.append(f"  {t('target_label'):<22}: {url}")
        lines.append(f"  {t('domain_label'):<22}: {domain}")
        lines.append(f"  {t('level_label'):<22}: {level.upper()}")
        lines.append(f"  {t('start_label'):<22}: {start_time}")
        lines.append(f"  {t('total_duration'):<22}: {duration}")
        lines.append(f"  {t('total_scans'):<22}: {stats.total}")
        lines.append(f"  {t('successful'):<22}: {stats.success}")
        lines.append(f"  {t('failed'):<22}: {stats.failed}")
        lines.append(f"  {t('success_label'):<22}: {stats.success_rate:.1f}%")
        lines.append(f"")
        lines.append(f"{'='*90}")
        lines.append(f"  {t('output_files')}")
        lines.append(f"{'='*90}")

        for desc, path in stats.files.items():
            if os.path.exists(path):
                size = os.path.getsize(path) / 1024
                lines.append(f"  • {desc:<45} → {Path(path).name} ({size:.1f} KB)")

        lines.append(f"")
        lines.append(f"{'='*90}")
        lines.append(f"  {t('recommendations')}")
        lines.append(f"{'='*90}")
        lines.append(f"  1. {t('rec_1')}")
        lines.append(f"  2. {t('rec_2')}")
        lines.append(f"  3. {t('rec_3')}")
        lines.append(f"  4. {t('rec_4')}")
        lines.append(f"  5. {t('rec_5')}")
        lines.append(f"  6. {t('rec_6')}")
        lines.append(f"")
        lines.append(f"{'='*90}")
        lines.append(f"  WSR v1.00 - Web Security Recon")
        lines.append(f"{'='*90}")

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
            f.write("\n")

    def generate_target_report_json(
        self,
        url: str,
        domain: str,
        level: str,
        start_time: datetime,
        scan_dir: Path,
        stats: ScanStatistics,
        report_file: str,
    ) -> None:
        duration = datetime.now() - start_time
        report_path = Path(report_file).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)

        report_data = {
            "wsr_version": "1.00",
            "target": {
                "url": url,
                "domain": domain,
            },
            "scan": {
                "level": level,
                "start_time": start_time.isoformat(),
                "duration_seconds": int(duration.total_seconds()),
                "duration_human": str(duration),
            },
            "statistics": {
                "total": stats.total,
                "success": stats.success,
                "failed": stats.failed,
                "success_rate": f"{stats.success_rate:.1f}%",
            },
            "output_files": {},
            "recommendations": [
                t("rec_1"),
                t("rec_2"),
                t("rec_3"),
                t("rec_4"),
            ],
        }

        for desc, path in stats.files.items():
            if os.path.exists(path):
                report_data["output_files"][desc] = {
                    "path": str(path),
                    "filename": Path(path).name,
                    "size_kb": round(os.path.getsize(path) / 1024, 1),
                }

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

    def generate_global_summary(
        self,
        scan_results: List[Dict[str, Any]],
        output_dir: str,
        start_time: datetime,
    ) -> str:
        summary_path = Path(output_dir).resolve() / "summary_report.txt"
        summary_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        lines.append(f"{'='*90}")
        lines.append(f"  WSR v1.00 - {t('multi_target_summary')}")
        lines.append(f"{'='*90}")
        lines.append(f"")
        lines.append(f"  {t('total_targets'):<22}: {len(scan_results)}")
        lines.append(f"  {t('start_label'):<22}: {start_time}")
        lines.append(f"  {t('report_title'):<22}: {datetime.now()}")
        lines.append(f"")
        lines.append(f"{'-'*90}")

        total_scans = 0
        total_success = 0
        total_failed = 0

        for i, result in enumerate(scan_results, 1):
            stats = result.get('stats')
            url = result.get('url', 'unknown')
            scan_dir = result.get('scan_dir', 'unknown')

            lines.append(f"")
            lines.append(f"  [{i}] {url}")
            lines.append(f"      {t('output_label')}  : {scan_dir}")
            if stats:
                lines.append(f"      {t('total_scans'):<11}: {stats.total} total, {stats.success} {t('successful')}, {stats.failed} {t('failed')}")
                lines.append(f"      {t('success_label'):<11}: {stats.success_rate:.1f}%")
                total_scans += stats.total
                total_success += stats.success
                total_failed += stats.failed

        lines.append(f"")
        lines.append(f"{'-'*90}")
        lines.append(f"  {t('grand_total')}: {total_scans} {t('total_scans')}, {total_success} {t('successful')}, {total_failed} {t('failed')}")
        if total_scans > 0:
            lines.append(f"  {t('overall_rate')}: {(total_success/total_scans)*100:.1f}%")
        lines.append(f"{'='*90}")

        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
            f.write("\n")

        return str(summary_path)

    def generate_global_summary_json(
        self,
        scan_results: List[Dict[str, Any]],
        output_dir: str,
        start_time: datetime,
    ) -> str:
        summary_path = Path(output_dir).resolve() / "summary_report.json"
        summary_path.parent.mkdir(parents=True, exist_ok=True)

        total_scans = 0
        total_success = 0
        total_failed = 0
        targets = []

        for result in scan_results:
            stats = result.get('stats')
            target_data = {
                "url": result.get('url', 'unknown'),
                "scan_dir": result.get('scan_dir', 'unknown'),
            }
            if stats:
                target_data["statistics"] = {
                    "total": stats.total,
                    "success": stats.success,
                    "failed": stats.failed,
                    "success_rate": f"{stats.success_rate:.1f}%",
                }
                total_scans += stats.total
                total_success += stats.success
                total_failed += stats.failed
            targets.append(target_data)

        summary_data = {
            "wsr_version": "1.00",
            "total_targets": len(scan_results),
            "start_time": start_time.isoformat(),
            "report_time": datetime.now().isoformat(),
            "grand_total": {
                "total_scans": total_scans,
                "total_success": total_success,
                "total_failed": total_failed,
                "success_rate": f"{(total_success/total_scans*100) if total_scans > 0 else 0:.1f}%",
            },
            "targets": targets,
        }

        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)

        return str(summary_path)


# ====================== BASE SCANNER ======================
class BaseScanner(ABC):
    def __init__(
        self,
        config: ScanConfig,
        executor: CommandExecutor,
        logger: Optional[WSRLogger] = None,
    ):
        self.config = config
        self.executor = executor
        self.logger = logger or WSRLogger.get_instance()

    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self, url: str, domain: str, scan_dir: Path) -> None:
        pass

    def _cmd_whatweb(self, url: str, scan_dir: Path):
        return {
            'cmd': ['whatweb', '-a', '1', url],
            'output_file': str(scan_dir / "whatweb.txt"),
            'description': "WhatWeb Technology Detection",
        }

    def _cmd_nmap_basic(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['nmap', '-sV', '-T2', domain],
            'output_file': str(scan_dir / "nmap_basic.txt"),
            'description': "Nmap Basic Service Scan",
        }

    def _cmd_sslscan(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['sslscan', domain],
            'output_file': str(scan_dir / "sslscan.txt"),
            'description': "SSL/TLS Security Analysis",
        }

    def _cmd_nikto(self, url: str, scan_dir: Path, tuning: str = "x"):
        return {
            'cmd': ['nikto', '-h', url, '-Tuning', tuning],
            'output_file': str(scan_dir / "nikto.txt"),
            'description': "Nikto Web Server Scan",
        }

    def _cmd_gobuster(self, url: str, wordlist: str, scan_dir: Path):
        return {
            'cmd': ['gobuster', 'dir', '-u', url, '-w', wordlist, '-t', '30', '-q'],
            'output_file': str(scan_dir / "gobuster.txt"),
            'description': "Gobuster Directory Enumeration",
        }

    def _cmd_ffuf(self, url: str, wordlist: str, scan_dir: Path, extra_args: Optional[list] = None):
        cmd = ['ffuf', '-u', f"{url}/FUZZ", '-w', wordlist, '-t', '50',
               '-mc', '200,301,302,403', '-fc', '404']
        if extra_args:
            cmd.extend(extra_args)
        return {
            'cmd': cmd,
            'output_file': str(scan_dir / "ffuf.txt"),
            'description': "FFUF Fast Fuzzing",
        }

    def _cmd_subfinder(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['subfinder', '-d', domain, '-o', str(scan_dir / 'subdomains.txt')],
            'output_file': None,
            'description': "Subfinder Subdomain Enumeration",
        }

    def _cmd_assetfinder(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['assetfinder', '--subs-only', domain],
            'output_file': str(scan_dir / "assetfinder.txt"),
            'description': "Assetfinder Subdomain Discovery",
        }

    def _cmd_amass(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['amass', 'enum', '-d', domain, '-o', str(scan_dir / 'amass.txt')],
            'output_file': None,
            'description': "Amass Asset Discovery",
        }

    def _cmd_httpx(self, scan_dir: Path):
        sub_file = str(scan_dir / 'subdomains.txt')
        live_file = str(scan_dir / 'live_hosts.txt')
        cmd_str = f"cat {shlex.quote(sub_file)} 2>/dev/null | httpx -silent -o {shlex.quote(live_file)}"
        return {
            'cmd': ['sh', '-c', cmd_str],
            'output_file': None,
            'description': "HTTPX Live Host Detection",
            'shell': True,
        }

    def _cmd_katana(self, url: str, scan_dir: Path):
        return {
            'cmd': ['katana', '-u', url, '-o', str(scan_dir / "katana.txt")],
            'output_file': str(scan_dir / "katana.txt"),
            'description': "Katana Web Crawling",
        }

    def _cmd_nmap_full(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['nmap', '-sV', '-sC', '-A', '-T4', '--script', 'vuln', domain],
            'output_file': str(scan_dir / "nmap_full.txt"),
            'description': "Nmap Advanced Vulnerability Scan",
        }

    def _cmd_ffuf_recursive(self, url: str, wordlist: str, scan_dir: Path):
        return {
            'cmd': ['ffuf', '-u', f"{url}/FUZZ", '-w', wordlist, '-t', '60',
                     '-recursion', '-recursion-depth', '2'],
            'output_file': str(scan_dir / "ffuf_recursive.txt"),
            'description': "FFUF Recursive Deep Fuzzing",
        }

    def _cmd_nuclei(self, url: str, scan_dir: Path):
        return {
            'cmd': ['nuclei', '-u', url, '-t', self.config.get_nuclei_templates_path(),
                     '-severity', 'low,medium,high', '-etags', 'intrusive',
                     '-o', str(scan_dir / 'nuclei.txt')],
            'output_file': str(scan_dir / "nuclei.txt"),
            'description': "Nuclei Template Scanning",
        }

    def _cmd_gau(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['gau', domain],
            'output_file': str(scan_dir / "gau.txt"),
            'description': "GAU Gather URLs",
        }

    def _cmd_waybackurls(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['waybackurls', domain],
            'output_file': str(scan_dir / "waybackurls.txt"),
            'description': "Waybackurls Historical URLs",
        }

    def _cmd_arjun(self, url: str, scan_dir: Path):
        return {
            'cmd': ['arjun', '-u', url, '-o', str(scan_dir / "arjun.txt")],
            'output_file': str(scan_dir / "arjun.txt"),
            'description': "Arjun Parameter Discovery",
        }

    def _cmd_dalfox(self, url: str, scan_dir: Path):
        return {
            'cmd': ['dalfox', 'url', url, '-o', str(scan_dir / "dalfox.txt")],
            'output_file': str(scan_dir / "dalfox.txt"),
            'description': "Dalfox XSS Scanner",
        }

    def _cmd_naabu(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['naabu', '-host', domain, '-o', str(scan_dir / "naabu.txt")],
            'output_file': str(scan_dir / "naabu.txt"),
            'description': "Naabu Fast Port Scanner",
        }

    def _cmd_dnsx(self, domain: str, scan_dir: Path):
        return {
            'cmd': ['dnsx', '-d', domain, '-o', str(scan_dir / "dnsx.txt")],
            'output_file': str(scan_dir / "dnsx.txt"),
            'description': "DNSX DNS Enumeration",
        }

    def _cmd_wafw00f(self, url: str, scan_dir: Path):
        return {
            'cmd': ['wafw00f', url, '-o', str(scan_dir / "wafw00f.txt")],
            'output_file': str(scan_dir / "wafw00f.txt"),
            'description': "WAFW00F WAF Detection",
        }

    def _cmd_gowitness(self, url: str, scan_dir: Path):
        return {
            'cmd': ['gowitness', 'single', url, '--screenshot-path', str(scan_dir)],
            'output_file': None,
            'description': "Gowitness Website Screenshot",
        }

    def _cmd_sqlmap(self, url: str, scan_dir: Path):
        return {
            'cmd': ['sqlmap', '-u', url, '--batch', '--level', '3', '--risk', '2',
                     '--dbs', '--threads=5'],
            'output_file': str(scan_dir / "sqlmap.txt"),
            'description': "SQLMap SQL Injection Test",
        }

    def _execute_cmd(self, cmd_dict: dict) -> str:
        return self.executor.run_with_delay(
            cmd_list=cmd_dict['cmd'],
            output_file=cmd_dict.get('output_file'),
            description=cmd_dict.get('description', ''),
            timeout=cmd_dict.get('timeout'),
            delay_min=self.config.scan_delay_min,
            delay_max=self.config.scan_delay_max,
            shell=cmd_dict.get('shell', False),
        )

    def _execute_cmds_parallel(self, cmd_list: list) -> dict:
        return self.executor.run_parallel(
            commands=cmd_list,
            delay_min=self.config.scan_delay_min,
            delay_max=self.config.scan_delay_max,
        )


# ====================== SLOW SCANNER ======================
class SlowScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Slow"

    def run(self, url: str, domain: str, scan_dir: Path) -> None:
        self.logger.subsection(t("slow_tests_start"))

        whatweb_cmd = self._cmd_whatweb(url, scan_dir)
        self._execute_cmd(whatweb_cmd)

        nmap_cmd = self._cmd_nmap_basic(domain, scan_dir)
        self._execute_cmd(nmap_cmd)

        if url.startswith('https://'):
            sslscan_cmd = self._cmd_sslscan(domain, scan_dir)
            self._execute_cmd(sslscan_cmd)

        nikto_cmd = self._cmd_nikto(url, scan_dir, tuning="1")
        self._execute_cmd(nikto_cmd)


# ====================== MEDIUM SCANNER ======================
class MediumScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Medium"

    def run(self, url: str, domain: str, scan_dir: Path) -> None:
        self.logger.subsection(t("medium_tests_start"))

        wordlist = str(self.config.get_wordlist_path(scan_dir))
        self.executor.download_wordlist(self.config.get_wordlist_url(), wordlist)

        gobuster_cmd = self._cmd_gobuster(url, wordlist, scan_dir)
        self._execute_cmd(gobuster_cmd)

        ffuf_cmd = self._cmd_ffuf(url, wordlist, scan_dir)
        self._execute_cmd(ffuf_cmd)

        subfinder_cmd = self._cmd_subfinder(domain, scan_dir)
        self._execute_cmd(subfinder_cmd)

        assetfinder_cmd = self._cmd_assetfinder(domain, scan_dir)
        self._execute_cmd(assetfinder_cmd)

        amass_cmd = self._cmd_amass(domain, scan_dir)
        self._execute_cmd(amass_cmd)

        httpx_cmd = self._cmd_httpx(scan_dir)
        self._execute_cmd(httpx_cmd)

        katana_cmd = self._cmd_katana(url, scan_dir)
        self._execute_cmd(katana_cmd)


# ====================== STRONG SCANNER ======================
class StrongScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Strong"

    def run(self, url: str, domain: str, scan_dir: Path) -> None:
        self.logger.subsection(t("strong_tests_start"))

        nmap_full_cmd = self._cmd_nmap_full(domain, scan_dir)
        self._execute_cmd(nmap_full_cmd)

        big_wordlist = str(self.config.get_big_wordlist_path(scan_dir))
        self.executor.download_wordlist(self.config.get_big_wordlist_url(), big_wordlist)

        ffuf_recursive_cmd = self._cmd_ffuf_recursive(url, big_wordlist, scan_dir)
        self._execute_cmd(ffuf_recursive_cmd)

        nuclei_cmd = self._cmd_nuclei(url, scan_dir)
        self._execute_cmd(nuclei_cmd)

        gau_cmd = self._cmd_gau(domain, scan_dir)
        self._execute_cmd(gau_cmd)

        waybackurls_cmd = self._cmd_waybackurls(domain, scan_dir)
        self._execute_cmd(waybackurls_cmd)

        arjun_cmd = self._cmd_arjun(url, scan_dir)
        self._execute_cmd(arjun_cmd)

        dalfox_cmd = self._cmd_dalfox(url, scan_dir)
        self._execute_cmd(dalfox_cmd)

        naabu_cmd = self._cmd_naabu(domain, scan_dir)
        self._execute_cmd(naabu_cmd)

        dnsx_cmd = self._cmd_dnsx(domain, scan_dir)
        self._execute_cmd(dnsx_cmd)

        wafw00f_cmd = self._cmd_wafw00f(url, scan_dir)
        self._execute_cmd(wafw00f_cmd)

        gowitness_cmd = self._cmd_gowitness(url, scan_dir)
        self._execute_cmd(gowitness_cmd)

        self.logger.warning(t("sqlmap_warning"))
        sqlmap_cmd = self._cmd_sqlmap(url, scan_dir)
        self._execute_cmd(sqlmap_cmd)


# ====================== MAIN SCANNER ======================
class WSRScanner:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.start_time = datetime.now()
        self.logger = WSRLogger.get_instance(
            verbose=self.config.verbose,
            quiet=self.config.quiet,
        )
        self.executor = CommandExecutor(
            logger=self.logger,
            timeout=self.config.get_timeout(),
        )
        self.installer = ToolInstaller(
            logger=self.logger,
            auto_install=self.config.auto_install,
        )
        self.reporter = ReportGenerator(logger=self.logger)
        self.session = SessionManager.get_instance()
        self.target_info_gatherer = TargetInfoGatherer(logger=self.logger)
        self._scanners = {}
        self._setup_signal_handler()

    def _setup_signal_handler(self) -> None:
        def handler(signum, frame):
            self.logger.error(t("interrupted"))
            sys.exit(1)
        signal.signal(signal.SIGINT, handler)

    def _select_language(self) -> None:
        if self.config.language:
            set_language(self.config.language)
            return
        print(f"\n{Colors.BOLD}{'='*50}{Colors.ENDC}")
        print(f"{Colors.BOLD}  WSR v{__version__}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*50}{Colors.ENDC}")
        print(f"\n{Colors.BOLD}{t('select_language')}{Colors.ENDC}")
        print(f"  1 - {t('lang_fa')}")
        print(f"  2 - {t('lang_en')}")
        choice = input(f"  > ").strip()
        if choice == '2':
            set_language("en")
        else:
            set_language("fa")

    def _get_scanner(self, level: str):
        scanner_map = {
            'slow': lambda: SlowScanner(self.config, self.executor, self.logger),
            'medium': lambda: MediumScanner(self.config, self.executor, self.logger),
            'strong': lambda: StrongScanner(self.config, self.executor, self.logger),
        }
        if level not in self._scanners:
            if level in scanner_map:
                self._scanners[level] = scanner_map[level]()
        return self._scanners.get(level)

    def _select_level(self) -> str:
        if self.config.level:
            return self.config.level

        print(f"\n{Colors.BOLD}{t('scan_level')}{Colors.ENDC}")
        print(f"  1. {t('level_slow')}")
        print(f"  2. {t('level_medium')}")
        print(f"  3. {t('level_strong')}")
        choice = input(f"  {t('select_level')}").strip()
        level_map = {'1': 'slow', '2': 'medium', '3': 'strong'}
        return level_map.get(choice, 'medium')

    def _get_targets(self) -> List[str]:
        if self.config.targets_file:
            targets_path = Path(self.config.targets_file)
            if targets_path.exists():
                with open(targets_path, 'r', encoding='utf-8') as f:
                    targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.logger.info(f"{t('targets_loaded')}: {len(targets)} {t('from_file')}: {self.config.targets_file}")
                return targets
            else:
                self.logger.error(f"{t('no_targets')}: {self.config.targets_file}")
                return []

        if self.config.target_url:
            return [self.config.target_url]

        target_input = input(
            f"{Colors.BOLD}{t('target_prompt')}{Colors.ENDC}"
        ).strip()

        if target_input.endswith('.txt') and os.path.exists(target_input):
            with open(target_input, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"{t('targets_loaded')}: {len(targets)} {t('from_file')}: {target_input}")
            return targets

        return [target_input]

    def _display_banner(self) -> None:
        self.logger.banner(random.choice(BANNERS))
        self.logger.banner(ASCII_BANNER)
        self.logger.info(f"{Colors.BOLD}   WSR v{__version__} - Web Security Recon | Iranian Bug Bounty Tool{Colors.ENDC}\n")

    def _install_tools(self) -> None:
        if self.config.skip_install:
            self.logger.info(t("skipping_tools"))
            return
        self.logger.section(t("installing_tools"))
        self.installer.install_all()
        self.installer.print_summary()

    def _display_scan_info(self, url: str, domain: str, level: str, scan_dir: Path) -> None:
        self.logger.section(f"{t('start_scan')}: {url}")
        self.logger.table_row(t("target_label"), url, Colors.CYAN)
        self.logger.table_row(t("domain_label"), domain, Colors.GREEN)
        self.logger.table_row(t("level_label"), level.upper(), Colors.YELLOW)
        self.logger.table_row(t("output_label"), str(scan_dir), Colors.WHITE)
        self.logger.table_row(t("start_label"), self.start_time.strftime("%Y-%m-%d %H:%M:%S"), Colors.WHITE)
        self.logger.table_row(t("session_id"), self.session.session_id, Colors.GRAY)
        self.logger.table_row(t("pid_label"), str(self.session.pid), Colors.GRAY)

    def _run_slow(self, url: str, domain: str, scan_dir: Path) -> None:
        scanner = self._get_scanner('slow')
        if scanner:
            scanner.run(url, domain, scan_dir)

    def _run_medium(self, url: str, domain: str, scan_dir: Path) -> None:
        scanner = self._get_scanner('medium')
        if scanner:
            scanner.run(url, domain, scan_dir)

    def _run_strong(self, url: str, domain: str, scan_dir: Path) -> None:
        scanner = self._get_scanner('strong')
        if scanner:
            scanner.run(url, domain, scan_dir)

    def _scan_target(self, target: str, level: str) -> Dict[str, Any]:
        try:
            url, parsed = validate_url(target)
        except ValueError as e:
            self.logger.error(str(e))
            return {'url': target, 'error': str(e), 'stats': None, 'scan_dir': None}

        domain = sanitize_domain(url)
        scan_dir, timestamp = create_scan_directory(self.config.output_dir, domain)
        report_file = str(scan_dir / f"wsr_report_{timestamp}.txt")

        resume = ResumeManager(str(scan_dir))
        resume.set_target(url)
        resume.set_level(level)

        self.logger.info(f"{t('gathering_info')}: {domain}")
        target_info = self.target_info_gatherer.gather(url, domain)
        self.target_info_gatherer.display(target_info)

        info_file = str(scan_dir / f"target_info_{timestamp}.json")
        try:
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(target_info, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        self._display_scan_info(url, domain, level, scan_dir)
        self.executor.reset_stats()

        if level == 'slow':
            if not resume.is_completed("slow"):
                self.logger.subsection(t("slow_tests_start"))
                self._run_slow(url, domain, scan_dir)
                resume.mark_completed("slow")
        elif level == 'medium':
            if not resume.is_completed("medium"):
                self.logger.subsection(t("medium_tests_start"))
                self._run_medium(url, domain, scan_dir)
                resume.mark_completed("medium")
        elif level == 'strong':
            if not resume.is_completed("strong"):
                self.logger.subsection(t("strong_tests_start"))
                self._run_strong(url, domain, scan_dir)
                resume.mark_completed("strong")

        self.reporter.generate_target_report(
            url=url,
            domain=domain,
            level=level,
            start_time=self.start_time,
            scan_dir=scan_dir,
            stats=self.executor.stats,
            report_file=report_file,
        )

        if self.config.report_format == "json":
            json_report = str(scan_dir / f"wsr_report_{timestamp}.json")
            self.reporter.generate_target_report_json(
                url=url,
                domain=domain,
                level=level,
                start_time=self.start_time,
                scan_dir=scan_dir,
                stats=self.executor.stats,
                report_file=json_report,
            )

        self.logger.success(
            f"{t('report_saved')}: {report_file}"
        )

        self.session.add_history(
            target=url,
            level=level,
            scan_dir=str(scan_dir),
            stats=self.executor.stats.summary_dict(),
        )

        return {
            'url': url,
            'domain': domain,
            'level': level,
            'scan_dir': str(scan_dir),
            'report_file': report_file,
            'stats': self.executor.stats,
        }

    def run(self) -> None:
        if self.config.no_color:
            enable_color(False)

        self._select_language()
        self._display_banner()
        self._install_tools()

        targets = self._get_targets()
        if not targets:
            self.logger.error(t("no_targets"))
            return

        level = self._select_level()
        self.logger.info(f"{t('selected_level')}: {Colors.BOLD}{level.upper()}{Colors.ENDC}")
        self.logger.info(f"{t('targets_count')}: {len(targets)}")

        scan_results: List[Dict[str, Any]] = []

        for i, target in enumerate(targets, 1):
            if len(targets) > 1:
                self.logger.section(f"Target {i}/{len(targets)}")
            result = self._scan_target(target, level)
            scan_results.append(result)

        if len(targets) > 1:
            summary_path = self.reporter.generate_global_summary(
                scan_results=scan_results,
                output_dir=self.config.output_dir,
                start_time=self.start_time,
            )
            if self.config.report_format == "json":
                self.reporter.generate_global_summary_json(
                    scan_results=scan_results,
                    output_dir=self.config.output_dir,
                    start_time=self.start_time,
                )
            self.logger.success(f"{t('summary_at')}: {summary_path}")

        duration = datetime.now() - self.start_time
        self.logger.section(t("final_results"))
        self.logger.table_row(t("targets_scanned"), str(len(scan_results)), Colors.CYAN)
        self.logger.table_row(t("total_duration"), format_duration(duration), Colors.GREEN)

        total_stats = sum(r['stats'].total for r in scan_results if r.get('stats'))
        total_success = sum(r['stats'].success for r in scan_results if r.get('stats'))
        self.logger.table_row(t("total_scans"), str(total_stats), Colors.WHITE)
        self.logger.table_row(t("successful"), str(total_success), Colors.GREEN)
        self.logger.table_row(t("failed"), str(total_stats - total_success), Colors.YELLOW)

        self.logger.success(t("all_complete"))
        self.logger.close()


# ====================== CLI ======================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wsr",
        description=f"WSR v{__version__} - Web Security Recon | Iranian Bug Bounty Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  wsr -t https://example.com
  wsr -t https://example.com -l strong
  wsr -t https://example.com --report json
  wsr -f targets.txt -l medium
  wsr -t https://example.com --auto-install --no-color
  wsr --config scan_config.json
  wsr -t https://example.com -o ./results --skip-install
        """,
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-t", "--target",
        type=str,
        default=None,
        help="Target URL to scan",
    )
    target_group.add_argument(
        "-f", "--file",
        type=str,
        default=None,
        dest="targets_file",
        help="File containing target URLs (one per line)",
    )

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "-l", "--level",
        type=str,
        choices=["slow", "medium", "strong"],
        default=None,
        help="Scan level: slow, medium, or strong (default: interactive selection)",
    )
    scan_group.add_argument(
        "-o", "--output",
        type=str,
        default="scans",
        help="Output directory for scan results (default: scans)",
    )
    scan_group.add_argument(
        "--delay-min",
        type=int,
        default=3,
        help="Minimum delay between scans in seconds (default: 3)",
    )
    scan_group.add_argument(
        "--delay-max",
        type=int,
        default=10,
        help="Maximum delay between scans in seconds (default: 10)",
    )

    tool_group = parser.add_argument_group("Tool Management")
    tool_group.add_argument(
        "--skip-install",
        action="store_true",
        default=False,
        help="Skip tool installation prompts",
    )
    tool_group.add_argument(
        "--auto-install",
        action="store_true",
        default=False,
        help="Auto-install missing tools without prompting",
    )

    lang_group = parser.add_argument_group("Language")
    lang_group.add_argument(
        "--lang",
        type=str,
        choices=["fa", "en"],
        default=None,
        help="Language: fa (Persian) or en (English)",
    )

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--report",
        type=str,
        choices=["text", "json"],
        default="text",
        dest="report_format",
        help="Report output format (default: text)",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress console output",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug output",
    )

    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to JSON configuration file",
    )

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    config = ScanConfig()

    if args.config:
        config = ScanConfig.from_file(args.config)

    if args.target:
        config.target_url = args.target
    if args.targets_file:
        config.targets_file = args.targets_file
    if args.level:
        config.level = args.level
    if args.output != "scans":
        config.output_dir = args.output
    if args.delay_min != 3:
        config.scan_delay_min = args.delay_min
    if args.delay_max != 10:
        config.scan_delay_max = args.delay_max
    if args.skip_install:
        config.skip_install = True
    if args.auto_install:
        config.auto_install = True
    if args.report_format != "text":
        config.report_format = args.report_format
    if args.no_color:
        config.no_color = True
    if args.quiet:
        config.quiet = True
    if args.verbose:
        config.verbose = True
    if args.lang:
        config.language = args.lang

    scanner = WSRScanner(config=config)
    scanner.run()


if __name__ == "__main__":
    main()
