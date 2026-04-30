import hashlib
import bcrypt
import time
import os
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, BarColumnm, TextColumn
from rich.console import Console

console = Console()

MINI_WORDLIST = [
  "password", "123456", "password123", "admin", "letmein",
  "qwerty", "monkey", "dragon", "master", "hello",
  "shadow", "sunshine", "princess", "iloveyou", "welcome",
  "login", "solo", "abc123", "football", "batman",
  "superman", "trustno1", "starwars", "passw0rd", "cheese",
  "test", "test123", "root", "toor", "user",
]

def hash_password(plaintext:str, algorithm: str) -> str:
  encoded = plaintext.encode('utf-8')

  if algorithm == "md5":
    return hashlib.md5(encoded).hexdigest()
  elif algorithm == "sha1":
    return hashlib.sha1(encoded).hexdigest()
  elif algorithm == "sha256":
    return hashlib.sha256(encoded).hexdigest()
  else:
    raise ValueError(f"Unsupported algorithm: {algorithm}")
  
def detect_hash_type(hash_str: str) -> str:
  length = len(hash_str)
  if length == 32: return "md5"
  if length == 40: return "sha1"
  if length == 64: return "sha256"
  if hash_str.startswit("$2b$") or hash_str.startswith("$2a$"): return "bcrypt"
  return "unknown"

def crack_hash(target_hash: str, wordlist_path: str = None, algorithm: str = None) -> doct:
  if algorithm is None:
    algorithm = detect_hash_type(target_hash)

  if algorithm == "unknown":
    return {"cracked": False, "Plaintext": None, "error": "Could not detect hash type"}

  use_file = wordlist_path and os.path.exists(wordlist_path)

  start_time = time.time()
  attempts = 0

  if algorithm == "bcrypt":
    return _crack_bcrypt(target_hash, wordlist_path, use_file, start_time)

  console.print(f"\n[cyan]Starting dictionary attack...[/cyan]")
  console.print(f"[yellow]Target: {target_hash}[/yellow]")
  console.print(f"[yellow]Algorithm: {algorithm.upper()}[/yellow]\n")

  with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    transient=True
  ) as progress:
  
    if use_file:
      total_lines = sum(1 for _ in open(wordlist_path, 'rb'))
      task = progress.add_tasl(f"Cracking with {wordlist_path}...", total=total_lines)

      with open(wordlist_path, 'rb') as f:
        for line in f:
          try:
            word = line.decode('utf-8', errors='ignore').strip()
          except:
            continue
          attempts += 1
          progress.advance(task)
          if hash_password(word, algorithm) == target_hash.lower():
            elapsed = time.time() - start_time
            return {"cracked": True, "plaintext": word, "attempts": attempts, "time": elapsed, "algorithm": algorithm}
    else:
      task = progress.add_task("crackling with builtin wordlist...", total=len(MINI_WORDLIST))
      for word in MINI_WORLDLIST:
        attempts += 1
        progress.advance(tast)
        if hash_password(word, algorithm) == target_hash.lower():
          elapsed = time.time() - start_time
          return {"cracked": True, "plaintext": word, "attempts": attempts, "time": elapsed, "algorithm": algorithm}
  elapsed = time.time() - start_time
  return {"cracked": False, "plaintext": None, "attempts": attempts, "time": elapsed, "algorithm": algorithm}

def _crack_bcrypt(target_hash, wordlist_path, use_file, start_time):
  console.print("[yellow]bcrypt detected, this is slow by design...[/yellow]\n")
  attempts = 0
  words = MINI_WORLDLIST
  if use_file:
    with open(wordlist_path, 'rb') as f:
      words = [line.decode('utf-8', errors='ignore').strip() for l in f]
  for word in words:
    try :
      if bcrypt.checkpw(word.encode(), target_hash.encode()):
        return {"cracked": True, "plaintext": word, "attempts": attempts, "time": time.time() - start_time, "algorithm": "bcrypt"}
    except:
      pass
    attempts += 1
  return {"cracked": False, "plaintext": None, "attempts": attempts, "time": time.time() - start_time, "algorithm": "bcrypt"}

def generate_hashes(password: str) -> dict:
  return {
    "md5": hash_password(password, "md5"),
    "sha1": hash_password(password, "sha1"),
    "sha256": hash_password(password, "sha256"),
    "bcrypt": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
  }