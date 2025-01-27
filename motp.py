import time
import json
import mitmproxy.http
from mitmproxy import ctx
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from threading import Thread
import subprocess
import os
from flask import Flask, render_template, jsonify

# Flask setup for real-time OTP dashboard
app = Flask(__name__)
otp_codes = []  # Store OTP codes here

# Define the websites to monitor for OTP requests
BLOCKED_SITES = ["paypal.com", "paypal.co.uk", "ebay.co.uk", "ebay.com", "clearpay.com", "amazon.co.uk", "amazon.com"]

# Class to handle OTP Blocking based on machine learning model
class AIOTPBlocking:
    def __init__(self):
        self.model = None
        self.model_file = "otp_model.pkl"
        self.data_file = "request_data.json"
        self.load_model()

    def load_model(self):
        """Load pre-trained model if available, otherwise initialize an empty model"""
        if os.path.exists(self.model_file):
            self.model = joblib.load(self.model_file)
        else:
            self.model = RandomForestClassifier()

    def save_model(self):
        """Save the current trained model to file"""
        joblib.dump(self.model, self.model_file)

    def train_model(self, data):
        """Train the model using the collected data"""
        if len(data) > 0:
            X = [d['features'] for d in data]
            y = [d['label'] for d in data]
            self.model.fit(X, y)
            self.save_model()

    def extract_features(self, flow):
        """Extract features from the HTTP request to feed into the ML model"""
        features = [flow.request.url, flow.request.method]
        return features

    def predict(self, flow):
        """Use the trained model to predict if a request is related to OTP"""
        if self.model:
            features = self.extract_features(flow)
            return self.model.predict([features])[0] == 1
        return False  # Default to False if no model is available

    def update_data(self, flow, is_otp):
        """Update request data for future training"""
        request_data = {
            "url": flow.request.url,
            "method": flow.request.method,
            "features": self.extract_features(flow),
            "label": 1 if is_otp else 0
        }
        with open(self.data_file, 'a') as file:
            json.dump(request_data, file)
            file.write('\n')

# Flask route to display intercepted OTP codes
@app.route('/otp_codes')
def otp_dashboard():
    return render_template('dashboard.html', otp_codes=otp_codes)

@app.route('/api/otp_codes')
def otp_codes_api():
    return jsonify(otp_codes)

# Mitmproxy addon to handle OTP detection and interception
class OTPDetectionAddon:
    def __init__(self, ai_blocking):
        self.ai_blocking = ai_blocking

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """Intercept each HTTP request and look for OTP requests"""
        if any(site in flow.request.host for site in BLOCKED_SITES):
            if self.ai_blocking.predict(flow):
                flow.response = mitmproxy.http.Response.make(
                    403, b"OTP/2FA Request Blocked", {"Content-Type": "text/plain"}
                )
                self.ai_blocking.update_data(flow, True)
                ctx.log.info(f"Blocked OTP request: {flow.request.url}")
            else:
                self.ai_blocking.update_data(flow, False)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """Intercept OTP responses and extract OTP codes"""
        # Look for OTP or 2FA related responses
        if flow.response.content:
            # Extract OTP from the response if it's included in the body or headers
            # This can be expanded with specific parsing methods depending on the website's OTP response format
            if b'OTP' in flow.response.content or b'2FA' in flow.response.content:
                otp_code = extract_otp_code(flow.response.content)
                if otp_code:
                    otp_codes.append(otp_code)
                    ctx.log.info(f"Intercepted OTP: {otp_code}")
                    # Optionally, update the real-time dashboard with Flask
                    update_dashboard(otp_code)

# Helper function to extract OTP from a response
def extract_otp_code(response_content):
    """A simple function to extract OTP from a response content"""
    import re
    # This is a very basic example; real-world applications need more sophisticated parsing
    otp_match = re.search(r'(\d{6})', response_content.decode('utf-8'))
    if otp_match:
        return otp_match.group(1)
    return None

def update_dashboard(otp_code):
    """Update OTP codes on the Flask dashboard"""
    otp_codes.append(otp_code)

# Function to start mitmproxy in a separate thread
def start_mitmproxy():
    ai_blocking = AIOTPBlocking()
    addon = OTPDetectionAddon(ai_blocking)
    options = mitmproxy.options.Options(listen_host='127.0.0.1', listen_port=8080)
    m = mitmproxy.controller.Master(options)
    m.addons.add(addon)
    m.run()

# Function to launch Firefox with Tor and proxy support
def open_firefox_session(use_tor=False, use_proxy=False):
    options = Options()
    options.headless = False
    options.add_argument("--private")
    options.add_argument("--incognito")
    options.set_preference("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    profile = webdriver.FirefoxProfile()
    
    if use_tor:
        profile.set_proxy({
            "proxyType": "MANUAL",
            "httpProxy": "127.0.0.1",
            "httpPort": 9050,
            "sslProxy": "127.0.0.1",
            "sslPort": 9050
        })
    
    if use_proxy:
        profile.set_proxy({
            "proxyType": "MANUAL",
            "httpProxy": "proxy_ip_address",
            "httpPort": "proxy_port",
            "sslProxy": "proxy_ip_address",
            "sslPort": "proxy_port"
        })
    
    driver = webdriver.Firefox(firefox_profile=profile, options=options)
    return driver

# Function to run everything in the background
def run_script():
    mitmproxy_thread = Thread(target=start_mitmproxy)
    mitmproxy_thread.daemon = True
    mitmproxy_thread.start()

    selenium_browsing()

# Example Selenium browsing to trigger OTP/2FA detection
def selenium_browsing():
    driver = open_firefox_session(use_tor=True)
    driver.get("https://www.paypal.com/signin")
    time.sleep(10)

    # Further interactions with OTP detection
    try:
        otp_field = driver.find_element(By.CSS_SELECTOR, 'input[type="text"][name*="otp"]')
        print("OTP field detected.")
    except Exception as e:
        print("OTP field not found:", str(e))

    driver.quit()

# Run the Flask app and start script simultaneously
if __name__ == "__main__":
    flask_thread = Thread(target=lambda: app.run(debug=True, use_reloader=False))
    flask_thread.daemon = True
    flask_thread.start()

    run_script()
