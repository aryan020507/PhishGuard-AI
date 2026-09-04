/**
 * Preset Demonstration Samples for PhishGuard-AI.
 * Enables one-click testing of legitimate vs. phishing URLs and messages.
 */

const URL_SAMPLES = [
  {
    label: "Legit: Wikipedia",
    type: "legit",
    url: "https://en.wikipedia.org/wiki/Computer_security"
  },
  {
    label: "Legit: GitHub Repo",
    type: "legit",
    url: "https://github.com/torvalds/linux/blob/master/Makefile"
  },
  {
    label: "Legit: Python Docs",
    type: "legit",
    url: "https://docs.python.org/3/library/urllib.parse.html"
  },
  {
    label: "Phish: IP Hostname",
    type: "phish",
    url: "http://192.168.1.100/paypal/login/verify-account.php?id=9942"
  },
  {
    label: "Phish: Credential Harvester",
    type: "phish",
    url: "http://appleid.apple.com.verify-billing-info.support-auth.com/login"
  },
  {
    label: "Phish: Shortened Link",
    type: "phish",
    url: "http://bit.ly/3xUrgentL0gin?redirect=bank-of-america-verify"
  }
];

const MESSAGE_SAMPLES = [
  {
    label: "Legit: Team Meeting",
    type: "legit",
    text: "Hey Aryan, are we still meeting in conference room 3 at 2:30 PM today?"
  },
  {
    label: "Legit: Doctor Appt",
    type: "legit",
    text: "Your dental checkup with Dr. Miller is scheduled for Thursday at 10:00 AM. Reply YES to confirm."
  },
  {
    label: "Legit: Package Delivered",
    type: "legit",
    text: "Your Amazon order #402-91823 was delivered to your front porch. Thank you for shopping."
  },
  {
    label: "Phish: Bank Lockout Scam",
    type: "phish",
    text: "URGENT: Your Wells Fargo account has been locked due to suspicious activity. Call 08712345678 immediately or update details at http://wellsfargo-verify.cc"
  },
  {
    label: "Phish: Lottery / Cash Lure",
    type: "phish",
    text: "CONGRATULATIONS! You were selected as today's $1,000 Walmart Gift Card winner. Claim your cash prize immediately at http://walmart-claim-reward.top"
  },
  {
    label: "Phish: Tax Refund Scam",
    type: "phish",
    text: "CRITICAL Notice from IRS: You have an unpaid tax refund of $1,420.50 waiting. Verify your identity within 24 hours to prevent court penalty: http://irs-refund-portal.biz"
  }
];
