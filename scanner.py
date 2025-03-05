#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, quote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

# Konfigurasi Logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class WebScanner:
    """
    Pemindai Kerentanan Web Tingkat Lanjut.

    Fitur:
    - Deteksi SQL Injection, XSS, LFI, SSRF, Open Directories.
    - Output terstruktur dengan tabel dan warna.
    - Mendukung verbose logging untuk debugging.
    - Penanganan kesalahan yang ditingkatkan.
    """

    def __init__(self, url, verbose=False):
        """
        Inisialisasi WebScanner.

        Args:
            url (str): URL target untuk pemindaian.
            verbose (bool): Aktifkan logging verbose untuk debugging.
        """
        self.url = url.rstrip("/")  # Pastikan tidak ada garis miring di akhir
        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme
        self.console = Console()
        self.verbose = verbose
        if verbose:
            logger.setLevel(logging.DEBUG)  # Atur level logger ke DEBUG jika verbose

    async def create_session(self):
        """
        Membuat sesi HTTP dengan header yang disesuaikan.

        Header dirancang untuk meniru browser dan menghindari deteksi.
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Referer": self.url,
            "X-Forwarded-For": "127.0.0.1",
        }
        return aiohttp.ClientSession(headers=headers)

    async def scan(self):
        """
        Menjalankan semua metode pemindaian dan menampilkan hasilnya.
        """
        self.console.print(f"\n[bold cyan]Memulai Pemindaian: {self.url}[/bold cyan]\n")

        vulnerabilities = {}  # Dictionary untuk menyimpan hasil kerentanan

        progress = Progress(transient=True)  # Inisialisasi progress bar
        task_id = progress.add_task("Pemindaian...", total=6)  # Tambahkan task untuk progress bar

        async with await self.create_session() as session:
            with progress:  # Aktifkan progress bar

                vulnerabilities["SQL Injection"] = await self.scan_sql_injection(session)
                progress.update(task_id, advance=1)

                vulnerabilities["XSS (Cross-Site Scripting)"] = await self.scan_xss(session)
                progress.update(task_id, advance=1)

                vulnerabilities["LFI (Local File Inclusion)"] = await self.scan_lfi(session)
                progress.update(task_id, advance=1)

                vulnerabilities["SSRF (Server-Side Request Forgery)"] = await self.scan_ssrf(session)
                progress.update(task_id, advance=1)

                vulnerabilities["File Sensitif"] = await self.scan_sensitive_files(session)
                progress.update(task_id, advance=1)

                vulnerabilities["Port Terbuka"] = await self.scan_open_ports()
                progress.update(task_id, advance=1)

        self.display_results(vulnerabilities)  # Tampilkan hasil setelah pemindaian selesai

    def display_results(self, vulnerabilities):
        """
        Menampilkan hasil pemindaian dalam format tabel yang terstruktur.

        Args:
            vulnerabilities (dict): Dictionary yang berisi hasil pemindaian.
        """
        table = Table(title="Hasil Pemindaian Web", title_style="bold magenta")
        table.add_column("Jenis Kerentanan", style="cyan", justify="left")
        table.add_column("Status", style="red", justify="center")

        for vuln, result in vulnerabilities.items():
            status = "[bold red]❌ Rentan[/bold red]" if result else "[bold green]✅ Aman[/bold green]"
            table.add_row(vuln, status)

        self.console.print(Panel(table, title="[bold yellow]Ringkasan Pemindaian[/bold yellow]"))

    async def send_request(self, session, url, method="GET", data=None):
        """
        Mengirim permintaan HTTP dengan penanganan kesalahan.

        Args:
            session (aiohttp.ClientSession): Sesi HTTP yang digunakan untuk permintaan.
            url (str): URL yang akan diminta.
            method (str): Metode HTTP (GET, POST, dll.). Default adalah GET.
            data (dict): Data yang akan dikirim dengan permintaan (untuk metode POST).

        Returns:
            tuple: Tuple yang berisi teks respons dan kode status. Mengembalikan (None, None) jika terjadi kesalahan.
        """
        try:
            async with session.request(method, url, data=data, timeout=10, ssl=False) as response:
                response.raise_for_status()  # Menaikkan HTTPError untuk kode status buruk (4xx atau 5xx)
                return await response.text(), response.status
        except aiohttp.ClientError as e:
            logger.warning(f"Gagal mengakses {url}: {e}")
            return None, None
        except Exception as e:
            logger.exception(f"Kesalahan tak terduga saat mengakses {url}: {e}")  # Log traceback lengkap
            return None, None

    async def scan_sql_injection(self, session):
        """
        Memeriksa kerentanan SQL Injection dengan payload yang berbeda.

        Args:
            session (aiohttp.ClientSession): Sesi HTTP untuk membuat permintaan.

        Returns:
            bool: True jika SQL Injection terdeteksi, False jika tidak.
        """
        payloads = ["' OR 1=1--", "' UNION SELECT NULL, version(), database(), user()--"]
        for payload in payloads:
            test_url = f"{self.url}?id={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and any(error in response.lower() for error in ["mysql", "syntax error", "sql syntax"]):
                self.console.print(f"[red]SQL Injection Ditemukan:[/red] {test_url}")
                if self.verbose:
                    logger.debug(f"URL percobaan SQL Injection: {test_url}")
                return True
        return False

    async def scan_xss(self, session):
        """
        Memeriksa kerentanan Cross-Site Scripting (XSS).

        Args:
            session (aiohttp.ClientSession): Sesi HTTP untuk membuat permintaan.

        Returns:
            bool: True jika XSS terdeteksi, False jika tidak.
        """
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in payloads:
            test_url = f"{self.url}?q={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and payload in response:
                self.console.print(f"[red]XSS Terdeteksi:[/red] {test_url}")
                if self.verbose:
                    logger.debug(f"URL percobaan XSS: {test_url}")
                return True
        return False

    async def scan_lfi(self, session):
        """
        Mendeteksi kerentanan Local File Inclusion (LFI).

        Args:
            session (aiohttp.ClientSession): Sesi HTTP untuk membuat permintaan.

        Returns:
            bool: True jika LFI terdeteksi, False jika tidak.
        """
        payloads = ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"]
        for payload in payloads:
            test_url = f"{self.url}?file={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and ("root:x:0:0" in response or "PGh0bWw" in response):  # Deteksi konten yang di-base64
                self.console.print(f"[red]LFI Terbuka:[/red] {test_url}")
                if self.verbose:
                    logger.debug(f"URL percobaan LFI: {test_url}")
                return True
        return False

    async def scan_ssrf(self, session):
        """
        Mendeteksi kerentanan Server-Side Request Forgery (SSRF).

        Args:
            session (aiohttp.ClientSession): Sesi HTTP untuk membuat permintaan.

        Returns:
            bool: True jika SSRF terdeteksi, False jika tidak.
        """
        payloads = ["http://127.0.0.1", "http://localhost", "http://example.com"]  # Tambahkan example.com untuk deteksi yang lebih baik
        for payload in payloads:
            test_url = f"{self.url}?url={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and (payload in response or "Example Domain" in response):  # Cari indikasi respons dari server eksternal
                self.console.print(f"[red]SSRF Ditemukan:[/red] {test_url}")
                if self.verbose:
                    logger.debug(f"URL percobaan SSRF: {test_url}")
                return True
        return False

    async def scan_sensitive_files(self, session):
        """
        Mengecek keberadaan file sensitif.

        Args:
            session (aiohttp.ClientSession): Sesi HTTP untuk membuat permintaan.

        Returns:
            bool: True jika file sensitif ditemukan, False jika tidak.
        """
        files = ["robots.txt", "config.php", "admin/", ".git/HEAD", ".env"]  # Tambahkan direktori admin/ dan .env
        for file in files:
            test_url = f"{self.url}/{file}"
            response, status = await self.send_request(session, test_url)
            if status == 200:
                self.console.print(f"[red]File Sensitif Ditemukan:[/red] {test_url}")
                if self.verbose:
                    logger.debug(f"URL file sensitif: {test_url}")
                return True
        return False

    async def scan_open_ports(self):
        """
        Memindai port terbuka di host target.

        Returns:
            bool: True jika ada port terbuka yang ditemukan, False jika tidak.
        """
        ports = [21, 22, 80, 443, 3306, 8080, 8443]  # Tambahkan port umum lainnya
        open_ports = []
        for port in ports:
            try:
                reader, writer = await asyncio.open_connection(self.host, port, ssl=False)  # Nonaktifkan SSL untuk semua port
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()  # Tunggu hingga socket tertutup sepenuhnya
                if self.verbose:
                    logger.debug(f"Port terbuka: {port}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Port tertutup atau tidak dapat diakses: {port} - {e}")
                pass
        if open_ports:
            self.console.print(f"[red]Port Terbuka:[/red] {open_ports}")
            return True
        return False

def main():
    """
    Titik masuk utama untuk skrip.
    """
    parser = argparse.ArgumentParser(description="Pemindai Kerentanan Web Tingkat Lanjut")
    parser.add_argument("url", help="URL target")
    parser.add_argument("-v", "--verbose", action="store_true", help="Aktifkan logging verbose")
    args = parser.parse_args()

    scanner = WebScanner(args.url, verbose=args.verbose)
    asyncio.run(scanner.scan())

if __name__ == "__main__":
    main()
