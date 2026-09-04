"""
Synthetic Dataset Generator for PhishGuard-AI.
Generates 100-row balanced synthetic datasets for URLs and Messages
for rapid validation, pipeline testing, and memory-safe training verification.
"""

import os
import pandas as pd
import numpy as np

DATA_DIR = os.path.dirname(os.path.abspath(__file__))

LEGIT_URLS = [
    "https://www.google.com/search?q=machine+learning",
    "https://github.com/torvalds/linux/commit/123456",
    "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://stackoverflow.com/questions/12345/how-to-train-ann",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.nature.com/articles/s41586-020-2649-2",
    "https://aws.amazon.com/ec2/instance-types/",
    "https://cloud.google.com/bigquery/docs/reference",
    "https://www.nytimes.com/section/technology",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.bbc.com/news/world-us-canada",
    "https://medium.com/@author/understanding-cybersecurity",
    "https://arxiv.org/abs/1706.03762",
    "https://pypi.org/project/tensorflow/",
    "https://hub.docker.com/_/python",
    "https://www.reddit.com/r/MachineLearning/",
    "https://news.ycombinator.com/item?id=3000000",
    "https://www.linkedin.com/in/cybersecurity-expert",
    "https://www.microsoft.com/en-us/security",
    "https://www.kaggle.com/datasets/phishing-urls",
    "https://gitlab.com/gitlab-org/gitlab/-/issues",
    "https://springer.com/journal/10207",
    "https://www.cloudflare.com/learning/security/what-is-phishing/",
    "https://www.coursera.org/learn/deep-learning",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
]

PHISH_URLS = [
    "http://192.168.1.100/paypal/login/verify-account.php?id=9942",
    "http://secure-banking-update.servehttp.com/chase/signin.htm",
    "http://appleid.apple.com.verify-billing-info.support-auth.com/login",
    "http://bit.ly/3xXp91Q?redirect=bank-of-america-urgent-login",
    "http://www-wellsfargo-security-alert.com/online/recovery.php",
    "http://218.45.12.89/webscr.php?cmd=_login-run&dispatch=5885d80a1",
    "http://netflix-billing-issue-update.top/account/renew-access",
    "http://amazon-prime-delivery-canceled.xyz/claim-refund/order?id=83",
    "http://account-verification-service-online.cc/signin/password-reset",
    "http://secure.ebayisapi.dll.account-update.tk/ebaysapi/confirm",
    "http://irs-tax-refund-pending-claim.biz/submit-taxpayer-id",
    "http://google-drive-shared-doc-view.link/authorize/login",
    "http://coinbase-wallet-security-breach.info/restore-keyphrase",
    "http://microsoft-outlook-web-access.xyz/owa/auth/logon.aspx",
    "http://urgent-notice-bank-alert.com:8080/secure/portal",
    "http://tinyurl.com/2p8xky4z?account=verify-suspended-card",
    "http://172.16.254.1/chase-online/cardmember/enroll",
    "http://dhl-express-package-redelivery-fee.club/track/shipment",
    "http://instagram-copyright-infringement-appeal.site/verify",
    "http://meta-business-suite-account-restricted.support-desk.top/login",
    "http://binance-account-freeze-warning.net/unlock/kyc",
    "http://royal-mail-delivery-fee-unpaid.info/pay-customs",
    "http://fidelity-investments-fraud-prevention.org/alert",
    "http://att-yahoo-mail-synchronization-error.biz/login",
    "http://paypal.com.customer-verification-portal.online/webscr",
]

LEGIT_MESSAGES = [
    "Hey Aryan, are we still meeting for coffee at 4pm today?",
    "Your appointment with Dr. Smith is confirmed for tomorrow at 10:30 AM.",
    "Thanks for sending over the project proposal, I will review it by Monday.",
    "Can you please pick up milk and bread on your way back from the store?",
    "The meeting has been rescheduled to Thursday afternoon at 2 PM.",
    "Hi mom, I arrived safely at the train station, see you in 20 minutes.",
    "Great job on the presentation today! The client was very impressed.",
    "Your package from Amazon was delivered to your front porch.",
    "Let me know when you are free for a quick sync call about the quarterly budget.",
    "The library book 'Clean Code' is due in 3 days. Please return or renew.",
    "Are you coming to John's birthday dinner on Saturday night?",
    "Here is the receipt for your grocery purchase at Whole Foods: $42.50.",
    "Don't forget to push your code changes to GitHub before ending today.",
    "Your flight AA1234 is on time. Gate departure is B22.",
    "Hey, did you catch the football game yesterday? Incredible ending!",
    "Your Uber ride is arriving in 3 minutes. Toyota Camry license plate XYZ123.",
    "Thanks for the dinner invitation, we would love to come over this weekend.",
    "The doctor's office called to let you know your test results came back normal.",
    "Can you email me the updated spreadsheet whenever you get a chance?",
    "Reminder: Team standup starts in 15 minutes in conference room 3.",
    "Good morning! Just checking in to see if you received the files I sent.",
    "Dinner was fantastic last night, thank you so much for hosting us!",
    "Your haircut appointment with Sarah is scheduled for Friday at 5pm.",
    "Please find attached the minutes from yesterday's engineering meeting.",
    "I'm running about 10 minutes late due to traffic, see you soon!",
]

PHISH_MESSAGES = [
    "URGENT: Your bank account has been locked due to suspicious activity. Click here to verify your identity: http://secure-bank.tk/verify",
    "CONGRATULATIONS! You have won a $1,000 Walmart Gift Card. Claim your prize immediately at http://walmart-winner.xyz/claim",
    "Alert from IRS: You have a pending tax refund of $1,420. Call 0800-123-456 immediately or visit http://irs-tax-gov.info/refund",
    "Your Netflix account is suspended due to billing error. Update your payment details now: http://netflix-renew-sub.top",
    "USPS: Your package could not be delivered due to incomplete address. Confirm details here or item will be returned: http://usps-track.cc",
    "FINAL WARNING: Your Apple ID is scheduled for deletion in 24 hours. Sign in now to cancel request: http://apple-auth-support.com",
    "Urgent security alert: Suspicious login from Moscow detected on your account. If this was not you, visit http://chase-protect.xyz/auth",
    "You have received a $500 bonus deposited into your crypto wallet. Withdraw your funds here: http://binance-claim.club",
    "Your debit card has been temporarily blocked for security reasons. Call our fraud department immediately on 08712345678.",
    "Dear customer, PayPal detected unauthorized access. Click to restore your access: http://paypal-resolution-center.biz",
    "CRITICAL: Unpaid toll invoice detected for license plate #4928. Pay immediately to avoid $150 court penalty: http://ezpass-pay.top",
    "Your parcel delivery has failed. A redelivery fee of $1.99 is required: http://dhl-express-redelivery.site",
    "Amazon Notice: Unrecognized order for iPhone 15 Pro ($999). If you did not make this purchase, call 1-800-FAKE-NUM immediately.",
    "URGENT: Your mobile plan will be terminated in 2 hours due to overdue balance. Pay instantly at http://att-payment-portal.info",
    "Winner! You were selected as today's lucky mobile user. Text YES to 88202 to receive your cash award now! Terms apply.",
    "Action Required: Your Wells Fargo security token has expired. Re-authenticate your account: http://wellsfargo-token.cc",
    "Security Notice: Someone attempted to change your Google account password. Confirm your identity: http://g-security-verify.net",
    "Bank of America Alert: Unusual charge of $749.00 at Target. Reply NO to decline or verify at http://bofa-fraud-unit.info",
    "Your lottery ticket matching draw #8932 won $50,000! Contact agent via WhatsApp +1234567890 to arrange your bank transfer.",
    "ALERT: Your social security number has been linked to criminal activity. Call our federal agent immediately at 800-555-0199.",
    "Your Facebook account will be disabled for policy violation. Appeal immediately within 24h at http://meta-appeal-desk.biz",
    "PayPal: You sent $850.00 to John Doe. If you did not authorize this, call us immediately at 1-888-299-1928.",
    "Claim your $750 Cash App reward today. Available to first 50 respondents only! Click http://cashapp-free-reward.top",
    "Warning: Your email storage quota is 99% full. Incoming messages will be bounced. Upgrade immediately at http://mail-quota-admin.xyz",
    "Important message from Citibank: Unrecognized debit card swipe in Nigeria. Click here to confirm card ownership: http://citi-secure.org",
]


def generate_synthetic_data():
    """Create 100-row balanced datasets for URLs and Messages."""
    os.makedirs(DATA_DIR, exist_ok=True)

    # 1. URL Dataset: Duplicate each list 2x to reach 50 legit + 50 phish = 100 rows
    urls_legit = LEGIT_URLS * 2
    urls_phish = PHISH_URLS * 2
    urls = urls_legit + urls_phish
    url_labels = [0] * len(urls_legit) + [1] * len(urls_phish)

    df_urls = pd.DataFrame({"url": urls, "label": url_labels})
    df_urls = df_urls.sample(frac=1.0, random_state=42).reset_index(drop=True)

    url_csv_path = os.path.join(DATA_DIR, "synthetic_urls.csv")
    df_urls.to_csv(url_csv_path, index=False)
    print(f"[OK] Created synthetic URLs dataset: {url_csv_path} ({len(df_urls)} rows)")

    # 2. Message Dataset: Duplicate each list 2x to reach 50 legit + 50 phish = 100 rows
    msgs_legit = LEGIT_MESSAGES * 2
    msgs_phish = PHISH_MESSAGES * 2
    msgs = msgs_legit + msgs_phish
    msg_labels = [0] * len(msgs_legit) + [1] * len(msgs_phish)

    df_msgs = pd.DataFrame({"message": msgs, "label": msg_labels})
    df_msgs = df_msgs.sample(frac=1.0, random_state=42).reset_index(drop=True)

    msg_csv_path = os.path.join(DATA_DIR, "synthetic_messages.csv")
    df_msgs.to_csv(msg_csv_path, index=False)
    print(f"[OK] Created synthetic Messages dataset: {msg_csv_path} ({len(df_msgs)} rows)")

    return url_csv_path, msg_csv_path


if __name__ == "__main__":
    generate_synthetic_data()
