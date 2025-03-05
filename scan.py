#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import logging
import socket
import ipaddress
from urllib.parse import urlparse, quote, urljoin
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.prompt import Confirm

# Advanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

class AdvancedWebScanner:
    """
    Comprehensive Web Vulnerability Scanner with Enhanced Detection Capabilities
    
    Features:
    - Advanced vulnerability detection techniques
    - Async scanning with performance optimization
    - Detailed reporting
    - Extensive logging
    """

    def __init__(self, target: str, verbose: bool = False):
        """
        Initialize the web scanner with advanced configuration.
        
        Args:
            target (str): Target URL or IP to scan
            verbose (bool): Enable detailed logging
        """
        self.target = target.rstrip("/")
        self.parsed_url = urlparse(target)
        self.host = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme
        self.console = Console()
        self.verbose = verbose
        
        # Enhanced logging
        if verbose:
            logger.setLevel(logging.DEBUG)

    async def create_session(self) -> aiohttp.ClientSession:
        """
        Create a sophisticated HTTP session with advanced headers.
        
        Returns:
            aiohttp.ClientSession: Configured HTTP session
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": self.target,
            "X-Forwarded-For": "127.0.0.1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        }
        return aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=15))

    async def scan(self) -> None:
        """
        Comprehensive vulnerability scanning process.
        """
        self.console.print(f"\n[bold cyan]🔍 Initiating Advanced Scan: {self.target}[/bold cyan]\n")

        vulnerabilities: Dict[str, List[str]] = {}

        async with await self.create_session() as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                scan_tasks = [
                    ("SQL Injection", self.scan_sql_injection(session)),
                    ("XSS Detection", self.scan_xss(session)),
                    ("LFI Vulnerability", self.scan_lfi(session)),
                    ("SSRF Vulnerability", self.scan_ssrf(session)),
                    ("Sensitive Files", self.scan_sensitive_files(session)),
                    ("Open Ports", self.scan_open_ports()),
                ]

                for description, task in scan_tasks:
                    task_id = progress.add_task(f"Scanning: {description}")
                    try:
                        result = await task
                        if result:
                            vulnerabilities[description] = result
                    except Exception as e:
                        logger.error(f"Error during {description} scan: {e}")
                        progress.log(f"[red]Error during {description} scan: {e}[/red]")
                    finally:
                        progress.remove_task(task_id)


        self.display_results(vulnerabilities)

    def display_results(self, vulnerabilities: Dict[str, List[str]]) -> None:
        """
        Enhanced result visualization with detailed reporting.
        
        Args:
            vulnerabilities (Dict[str, List[str]]): Detected vulnerabilities
        """
        if not vulnerabilities:
            self.console.print("[bold green]✅ No Vulnerabilities Detected![/bold green]")
            return

        panel_title = "[bold yellow]🚨 Vulnerability Report[/bold yellow]"
        
        table = Table(title="Vulnerability Details", show_lines=True)
        table.add_column("Vulnerability Type", style="cyan")
        table.add_column("Detailed Findings", style="magenta")

        for vuln_type, findings in vulnerabilities.items():
            table.add_row(vuln_type, "\n".join(findings))

        risk_panel = Panel(
            table, 
            title=panel_title, 
            border_style="red", 
            expand=False
        )
        
        self.console.print(risk_panel)
        
        # Optional: Confirm for detailed report generation
        if Confirm.ask("Generate detailed vulnerability report?"):
            self.generate_report(vulnerabilities)

    def generate_report(self, vulnerabilities: Dict[str, List[str]]) -> None:
        """
        Generate a comprehensive vulnerability report.
        
        Args:
            vulnerabilities (Dict[str, List[str]]): Detected vulnerabilities
        """
        report_filename = f"vulnerability_report_{self.host}.txt"
        with open(report_filename, 'w') as f:
            f.write(f"Vulnerability Report for {self.target}\n")
            f.write("=" * 50 + "\n\n")
            for vuln_type, findings in vulnerabilities.items():
                f.write(f"{vuln_type}:\n")
                for finding in findings:
                    f.write(f"  - {finding}\n")
                f.write("\n")
        
        self.console.print(f"[bold green]📄 Report generated: {report_filename}[/bold green]")

    async def scan_sql_injection(self, session: aiohttp.ClientSession) -> Optional[List[str]]:
        """
        Advanced SQL Injection detection.
        
        Returns:
            Optional[List[str]]: List of vulnerable endpoints
        """
        payloads = [
            "' OR 1=1--", 
            "' UNION SELECT NULL, version(), database(), user()--",
            "1' OR '1'='1",
        ]
        vulnerable_endpoints = []

        for payload in payloads:
            params = {"id": payload, "search": payload}
            try:
                async with session.get(self.target, params=params) as response:
                    content = await response.text()
                    if any(keyword in content.lower() for keyword in ["mysql", "syntax error", "sql syntax"]):
                        vulnerable_endpoints.append(f"Endpoint: {response.url}")
            except aiohttp.ClientError as e:
                logger.error(f"Error during SQL Injection scan: {e}")

        return vulnerable_endpoints or None

    async def scan_xss(self, session: aiohttp.ClientSession) -> Optional[List[str]]:
        """
        Advanced XSS detection.
        
        Returns:
            Optional[List[str]]: List of vulnerable endpoints
        """
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        vulnerable_endpoints = []

        for payload in payloads:
            # Try injecting the payload into various parameters
            params = {"q": payload, "search": payload, "input": payload}
            try:
                async with session.get(self.target, params=params) as response:
                    content = await response.text()
                    if payload in content:
                        vulnerable_endpoints.append(f"Endpoint: {response.url}")
            except aiohttp.ClientError as e:
                logger.error(f"Error during XSS scan: {e}")

        return vulnerable_endpoints or None

    async def scan_lfi(self, session: aiohttp.ClientSession) -> Optional[List[str]]:
        """
        Placeholder for LFI vulnerability scanning.  Implement the actual logic here.
        """
        # TODO: Implement LFI scanning logic
        logger.warning("LFI scanning not fully implemented yet.")
        return None

    async def scan_ssrf(self, session: aiohttp.ClientSession) -> Optional[List[str]]:
        """
        Placeholder for SSRF vulnerability scanning. Implement the actual logic here.
        """
        # TODO: Implement SSRF scanning logic
        logger.warning("SSRF scanning not fully implemented yet.")
        return None

    async def scan_sensitive_files(self, session: aiohttp.ClientSession) -> Optional[List[str]]:
        """
        Placeholder for sensitive files scanning. Implement the actual logic here.
        """
        # TODO: Implement sensitive files scanning logic
        logger.warning("Sensitive files scanning not fully implemented yet.")
        return None

    async def scan_open_ports(self) -> Optional[List[str]]:
        """
        Placeholder for open ports scanning. Implement the actual logic here.
        """
        # TODO: Implement open ports scanning logic
        logger.warning("Open ports scanning not fully implemented yet.")
        return None

def main():
    """
    Main entry point with advanced argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="🕵️ Advanced Web Vulnerability Scanner",
        epilog="Scan responsibly and only on systems you own or have explicit permission."
    )
    parser.add_argument("target", help="Target URL or IP address")
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging and debugging"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Custom request timeout in seconds"
    )
    
    args = parser.parse_args()

    try:
        scanner = AdvancedWebScanner(args.target, verbose=args.verbose)
        asyncio.run(scanner.scan())
    except Exception as e:
        logger.error(f"Scan failed: {e}")

if __name__ == "__main__":
    main()
