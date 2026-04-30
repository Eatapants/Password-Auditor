import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from strength import score_password
from cracker import crack_hash, generate_hashes, detect_hash_type
from report import generate_report

console = Console()

def print_banner():
  banner = """
 ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
 ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
 ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
 ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
            AUDITOR & HASH CRACKER — For authorized use only
"""
  console.print(Panel(banner, style="bold cyan"))

def audit_single_password(password:str, wordlist: str = None) -> dict:
  console.print(f"\n[cyan]Auditing password: [/cyan] [yellow]{password}[/yellow]")
  console.print("-" * 60)

  strength = score_password(password)
  hashes = generate_hashes(password)
  crack_result = crack_hash(hashes["md5"], wordlist, "md5")

  table = Table(show_header=True, header_style="bold cyan")
  table.add_column("Property", style="dim")
  table.add_column("Value")

  grade_color = {"A":"green","B":"bright_green","C":"yellow", "D":"orange1","F":"red"}.get(strength.grade, "white")
  table.add_row("Grade", f"[{grade_color}]{strength.grade}[/{grade_color}]")
  table.add_row("Score", f"{strength.score}/100")
  table.add_row("Entropy", f"{strength.entropy} bits")
  table.add_row("Charset", f"{strength.charset_size} characters")
  table.add_row("Length", f"{len(password)}")
  table.add_row("MD5 Hash", f"[dim]{hashes['md5']}[/dim]")
  table.add_row("SHA256 Hash", f"[dim]{hashes['sha256'][:32]}...[/dim]")

  crack_status = {
    f"[red]✗ CRACKED in {crack_result['attempts']:,} attempts ({crack_result['time_taken']:.2f}s)[/red]"
    if crack_result["cracked"] else
    f"[green]✓ Not found in wordlist ({crack_result['attempts']:,}tested [/green]"
  }
  table.add_row("Dictionary", crack_status)
  table.add_row("MD5 Crack EST.", strength.crack_time)

  if strength.patterns:
    table.add_row("Weak Patterns", "\n".join(f"[red]⚠[/red] {p}" for p in strength.patterns))
  
  console.print(table)
  console.print("\n[bold cyan] Recommendations: [/bold cyan]")

  for s in strength.suggestions:
    console.print(f"[green]✓[/green] {s}")
  return {
    "password": password,
    "score": strength.score,
    "grade": strength.grade,
    "entropy": strength.entropy,
    "crack_time": strength.crack_time,
    "suggestions": strength.suggestions,
    "patterns": strength.patterns,
  }

def audit_from_file(file_path: str, wordlist: str = None) -> list:
  with open(filepath, "r") as f:
    passwords = [line.strip() for line in f if line.strip()]
  console.print(f"[cyan] Loaded {len(passwords)} passwords from {file_path} [/cyan]\n")
  return [audit_single_password(p, wordlist) for p in passwords]

def demo_mode():
  demo_passwords = [
    "password",      
    "hello123",       
    "P@ssw0rd!",      
    "correct-horse-battery",
    "Xk7#mP2!qL9$vR4@",
  ]
    
  console.print(Panel("[bold green]DEMO MODE — Testing 5 example passwords[/bold green]"))
  results = []
  for pw in demo_passwords:
    results.append(audit_single_password(pw))
  return results

def main():
  print_banner()

  parser = argparse.ArgumentParser(
    description="Password Auditor & Hash Cracker — authorized security testing only"
  )
  parser.add_argument("--password", "-p", help="Audit a single password")
  parser.add_argument("--hash", help="Attempt to crack a hash")
  parser.add_argument("--file", "-f", help="File with one password per line")
  parser.add_argument("--wordlist", "-w", help="Path to wordlist (e.g. rockyou.txt)")
  parser.add_argument("--report", "-r", help="Output HTML report to this path", default="report.html")
  parser.add_argument("--generate", help="Generate all hashes for a plaintext password")
  parser.add_argument("--demo", action="store_true", help="Run demo on example passwords")
  args = parser.parse_args()

  results = []

  if args.generate:
    hashes = generate_hashes(args.generate)
    console.print(f"\n[bold cyan]Hashes for:[/bold cyan] [yellow]{args.generate}[/yellow]")
    for algo, h in hashes.items():
      console.print(f"  [green]{algo.upper():<8}[/green] {h}")
      sys.exit(0)

  elif args.hash:
    result = crack_hash(args.hash, args.wordlist)
    if result["cracked"]:
      console.print(f"\n[red bold]✗ CRACKED![/red bold] Plaintext: [yellow]{result['plaintext']}[/yellow]")
    else:
      console.print("\n[green]✓ Not found in wordlist.[/green]")
      sys.exit(0)

  elif args.password:
    results = [audit_single_password(args.password, args.wordlist)]

  elif args.file:
    results = audit_from_file(args.file, args.wordlist)

  elif args.demo:
    results = demo_mode()

  else:
    parser.print_help()
    sys.exit(0)

  if results:
    report_path = generate_report(results, args.report)
    console.print(f"\n[bold green]✓ Report saved to:[/bold green] {report_path}")
    console.print("[dim]Open it in your browser to view the full audit.[/dim]\n")


if __name__ == "__main__":
  main()