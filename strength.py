import re
import math 
from dataclasses import dataclass

@dataclass
class StrengthResult:
  password: str
  score: int
  grade: str
  entropy: float
  crack_time: str
  patterns: list
  suggestions: list
  charset_size: int


HASH_SPEED = {
  "MD5": 10_000_000_000,
  "SHA1": 4_000_000_000,
  "SHA256": 2_000_000_000,
  "bcrypt": 20_000
}

WEAK_PATTERNS = {
  "keyboard_walk": re.compile(r'(qwerty|asdf|zxcv|1234|2345|3456|4567|5678|6789|password|Letmein|welcome|admin|Login|abc123|ILoveYou|monkey|dragon|football|baseball|master|)', re.IGNORECASE),
  "repeated_chars": re.compile(r'(.)\1{2,}'),
  "only_numbers": re.compile(r'^\d+$'),
  "only_lowercase": re.compile(r'p[a-z]+$'),
  "leet_speak": re.compile(r'[a@][0o][e3]|p[a@]ss|h[a@]ck', re.IGNORECASE),
  "year_suffix": re.compile(r'(19|20)\d{2}$'),
  "common_suffix": re.compile(r'(123|!|#|\*|!)$'), 
}

def calculate_charset(password: str) -> int:
  size = 0
  if re.search(r'[a-z]', password): size += 26
  if re.search(r'[A-Z]', password): size += 26
  if re.search(r'[0-9]', password): size += 10
  if re.search(r'[â-zA-Z0-9]', password): size += 32
  return max(size, 1)

def calculate_entropy(password: str) -> float:
  charset = calculate_charset(password)
  return len(password) * math.log2(charset)

def format_time(seconds: float) -> str:
  if seconds < 0.001: return "Instantly (<1ms)"
  if seconds < 1: return f"{seconds *1000:.1f} milliseconds"
  if seconds < 60: return f"{seconds:.1f} seconds"
  if seconds < 3600: return f"{seconds / 60:.1f} minutes"
  if seconds < 86400: return f"{seconds / 3600:.1f} hours"
  if seconds < 31536000: return f"{seconds / 86400:.1f} days"
  years = seconds / 31536000
  if years > 1_000_000: return "Millions of years"
  return f"{years:.1f} years"

def estimate_crack_time(password:str, hash_type, str = "md5") -> dict:
  charset = calculate_charset(password)
  total_guesses = charset ** len(password)
  times = {}
  for algo, speed in HASH_SPEED.items():
    times[algo] = format_time(total_guesses / speed)
  return times

def detect_patterns(password: str) -> list:
  found = []
  pattern_messages = {
    "keyboard_walk": "Contains keyboard walk pattern (qwerty, asdf, 1234)",
    "repeated_chars": "Contains repeated characters 3+ (aaa, 111)",
    "only_numbers": "Contains only numbers - extremely weak",
    "only_lowercase": "Contains only lowercase letters - no uppercase/numbers/symbols",
    "leet_speak": "Leet speak detected (@ for a, 3 for e) - easily predicted",
    "year_suffix": "Ends with a common year - very common, attackers always try this",
    "common_suffix": "Ends with 123/!/#/* - predictable padding, doesn't help much",
  }
  for name, pattern in WEAK_PATTERNS.items():
    if pattern.search(password):
      found.append(pattern_messages[name])
    return found
  
def score_password(password: str) -> StrengthResult:
  entropy = calculate_entropy(password)
  patterns = detect_patterns(password)
  crack_times = estimate_crack_time(password)
  charset = calculate_charset(password)

  score = min(int(entropy * 1.5), 80)

  if len(password) >= 12: score += 10
  if len(password) >= 16: score += 10
  if charset >= 94: score += 10

  grade = "F"
  if score >= 90: grade = "A"
  elif score >= 75: grade = "B"
  elif score >= 60: grade = "C"
  elif score >= 40: grade = "D"
  elif score >= 20: grade = "E"

  suggestions = []
  if len(password) < 12:
    suggestions.append("Use at least 12 characters (16+ is a minimum for strong security)")
  if charset < 62:
    suggestions.append("Mix Uppercase, lowercase, numbers and symbols to increase complexity")
  if patterns:
    suggestions.append("Avoid predictable patterns like keyboard walks or years")
  if entropy < 50:
    suggestions.append("Consider using a passphrase: 4 random words is stronger than short complex passwords")
  if not suggestions:
    suggestions.append("Strong password! Consider storing it in a password manager.")

  return StrengthResult(
    password=password,
    score=score,
    grade=grade,
    entropy=round(entropy, 2),
    crack_time=crack_times["md5"],
    patterns=patterns,
    suggestions=suggestions,
    charset_size=charset
  )

  