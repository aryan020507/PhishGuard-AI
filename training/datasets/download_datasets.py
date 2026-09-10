"""
Dataset Downloader & Parser for PhishGuard-AI.
Fetches and standardizes:
1. UCI SMS Spam Collection (ham=0, spam=1)
2. PhishTank & Tranco URL feeds (legitimate=0, phishing=1)

Includes automatic fallback and --use-synthetic flag for lightweight internal validation.
"""

import os
import io
import zipfile
import argparse
import urllib.request
import pandas as pd
try:
    from training.datasets.generate_synthetic import generate_synthetic_data
except ImportError:
    from generate_synthetic import generate_synthetic_data

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
UCI_SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
# Mirror/alternative in case UCI direct archive is throttled
UCI_SMS_MIRROR = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"

URLS_DATASET_CSV = os.path.join(DATA_DIR, "urls_dataset.csv")
MESSAGES_DATASET_CSV = os.path.join(DATA_DIR, "messages_dataset.csv")


def download_sms_dataset() -> pd.DataFrame:
    """Download and parse the UCI SMS Spam Collection."""
    print("[*] Fetching UCI SMS Spam Collection...")
    headers = {"User-Agent": "PhishGuard-AI/1.0"}

    # Attempt 1: Raw TSV Mirror
    try:
        req = urllib.request.Request(UCI_SMS_MIRROR, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8", errors="ignore")
            df = pd.read_csv(io.StringIO(content), sep="\t", header=None, names=["label_str", "message"])
            df["label"] = df["label_str"].map({"ham": 0, "spam": 1})
            df = df.dropna(subset=["label", "message"])
            df["label"] = df["label"].astype(int)
            df = df[["message", "label"]]
            print(f"[OK] Downloaded UCI SMS Spam via mirror ({len(df)} samples)")
            return df
    except Exception as e:
        print(f"[-] Mirror failed: {e}. Trying official UCI zip archive...")

    # Attempt 2: Official UCI Zip
    try:
        req = urllib.request.Request(UCI_SMS_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as response:
            zip_bytes = io.BytesIO(response.read())
            with zipfile.ZipFile(zip_bytes) as z:
                with z.open("SMSSpamCollection") as f:
                    content = f.read().decode("utf-8", errors="ignore")
                    df = pd.read_csv(io.StringIO(content), sep="\t", header=None, names=["label_str", "message"])
                    df["label"] = df["label_str"].map({"ham": 0, "spam": 1})
                    df = df.dropna(subset=["label", "message"])
                    df["label"] = df["label"].astype(int)
                    df = df[["message", "label"]]
                    print(f"[OK] Downloaded UCI SMS Spam from archive ({len(df)} samples)")
                    return df
    except Exception as e:
        print(f"[-] Could not download real SMS dataset: {e}. Falling back to synthetic.")
        _, syn_msg = generate_synthetic_data()
        return pd.read_csv(syn_msg)


def download_url_dataset() -> pd.DataFrame:
    """
    Fetch/parse verified URLs:
    - Phishing: OpenPhish verified public feed
    - Legitimate: Official dotgov verified domains + top sites
    """
    print("[*] Fetching real-world URL feeds...")
    headers = {"User-Agent": "PhishGuard-AI/1.0"}

    phish_urls = []
    legit_urls = []

    # 1. OpenPhish live feed
    try:
        phish_feed_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        req = urllib.request.Request(phish_feed_url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as response:
            lines = response.read().decode("utf-8", errors="ignore").strip().splitlines()
            phish_urls = [line.strip() for line in lines if line.strip() and line.startswith("http")]
            print(f"[OK] Fetched {len(phish_urls)} phishing URLs from OpenPhish feed")
    except Exception as e:
        print(f"[-] OpenPhish feed error: {e}")

    # 2. Legitimate domains with realistic paths
    COMMON_BENIGN_PATHS = [
        "",
        "",
        "watch?v=dQw4w9WgXcQ",
        "search?q=open+source+software",
        "explore",
        "feed/trending",
        "docs/reference/api-overview.html",
        "wiki/Artificial_intelligence",
        "products/electronics/catalog",
        "articles/2026/04/technology-news",
        "category/science-and-nature",
        "user/profile/settings",
        "blog/cybersecurity-best-practices",
        "news/international-headlines",
        "faq/frequently-asked-questions",
        "about-us/company-overview",
        "resources/whitepapers/cloud-architecture",
        "community/discussions/general",
        "releases/v3.4.1/changelog.md",
    ]

    POPULAR_DOMAINS = [
        "youtube.com", "google.com", "wikipedia.org", "github.com", "stackoverflow.com", "python.org",
        "microsoft.com", "amazon.com", "apple.com", "netflix.com", "bbc.com", "reddit.com", "coursera.org",
        "cloudflare.com", "mozilla.org", "w3schools.com", "nytimes.com", "arxiv.org",
        "cnn.com", "apache.org", "docker.com", "medium.com", "linkedin.com"
    ]

    try:
        legit_gov_url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv"
        req = urllib.request.Request(legit_gov_url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as response:
            content = response.read().decode("utf-8", errors="ignore")
            df_gov = pd.read_csv(io.StringIO(content))
            col_name = "Domain Name" if "Domain Name" in df_gov.columns else df_gov.columns[0]
            domains = list(df_gov[col_name].dropna().unique())
            all_domains = POPULAR_DOMAINS + [d.lower().strip() for d in domains]

            # Construct standard HTTPS URLs with natural path and subdomain distribution
            import random
            random.seed(42)
            target_count = len(phish_urls) if phish_urls else 1000
            for i in range(target_count):
                dom = all_domains[i % len(all_domains)]
                path = random.choice(COMMON_BENIGN_PATHS)
                # 50% use www, 50% use apex domain (without www)
                use_www = random.random() < 0.5
                prefix = "https://www." if use_www else "https://"
                full_url = f"{prefix}{dom}/{path}" if path else f"{prefix}{dom}/"
                legit_urls.append(full_url)

            print(f"[OK] Fetched {len(legit_urls)} realistic legitimate URLs")
    except Exception as e:
        print(f"[-] Legitimate feed error: {e}")

    if phish_urls and legit_urls:
        # Balance dataset size
        min_len = min(len(phish_urls), len(legit_urls))
        p_sample = phish_urls[:min_len]
        l_sample = legit_urls[:min_len]
        urls = l_sample + p_sample
        labels = [0] * len(l_sample) + [1] * len(p_sample)
        df = pd.DataFrame({"url": urls, "label": labels})
        df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
        print(f"[OK] Created balanced URL dataset ({len(df)} samples: {len(l_sample)} legit, {len(p_sample)} phish)")
        return df

    print("[-] Falling back to synthetic URLs dataset.")
    syn_url, _ = generate_synthetic_data()
    return pd.read_csv(syn_url)


def prepare_datasets(use_synthetic: bool = False):
    """Ensure datasets are ready on disk."""
    if use_synthetic:
        print("[*] Generating 100-row synthetic test datasets...")
        syn_url, syn_msg = generate_synthetic_data()
        df_urls = pd.read_csv(syn_url)
        df_msgs = pd.read_csv(syn_msg)
    else:
        df_urls = download_url_dataset()
        df_msgs = download_sms_dataset()

    df_urls.to_csv(URLS_DATASET_CSV, index=False)
    df_msgs.to_csv(MESSAGES_DATASET_CSV, index=False)
    print(f"[SUCCESS] Datasets prepared:\n - URLs: {URLS_DATASET_CSV} ({len(df_urls)} rows)\n - Messages: {MESSAGES_DATASET_CSV} ({len(df_msgs)} rows)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download and prepare datasets for PhishGuard-AI")
    parser.add_argument("--synthetic", action="store_true", help="Generate synthetic 100-row datasets for fast testing")
    args = parser.parse_args()
    prepare_datasets(use_synthetic=args.synthetic)
