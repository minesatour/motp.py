import time
import json
import mitmproxy
from mitmproxy import ctx
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.proxy import Proxy, ProxyType
from threading import Thread
from collections import deque

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
        # You can add more sophisticated feature extraction here if needed
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

# Mitmproxy addon to block OTP requests
class BlockOTPRequestsAddon:
    def __init__(self, ai_blocking):
        self.ai_blocking = ai_blocking

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """Intercept each HTTP request and block OTP requests"""
        if any(site in flow.request.host for site in BLOCKED_SITES):
            if self.ai_blocking.predict(flow):
                flow.response = mitmproxy.http.Response.make(
                    403, b"OTP Request Blocked", {"Content-Type": "text/plain"}
                )
                self.ai_blocking.update_data(flow, True)
                ctx.log.info(f"Blocked OTP request: {flow.request.url}")
            else:
                self.ai_blocking.update_data(flow, False)

# Function to start mitmproxy in a separate thread
def start_mitmproxy():
    ai_blocking = AIOTPBlocking()
    addon = BlockOTPRequestsAddon(ai_blocking)
    options = mitmproxy.options.Options(listen_host='127.0.0.1', listen_port=8080)  # Updated for newer mitmproxy
    m = mitmproxy.controller.Master(options)
    m.addons.add(addon)
    m.run()

# Function to open a Firefox session with the configured proxy (Tor support)
def open_firefox_session(use_tor=False):
    # Set up Firefox options
    options = Options()
    options.headless = False  # Set to True for headless browsing

    # Configure proxy settings to route through Tor if necessary
    if use_tor:
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = '127.0.0.1:9050'  # Tor SOCKS proxy
        proxy.socks_proxy = '127.0.0.1:9050'  # Tor SOCKS proxy for all protocols
        proxy.ssl_proxy = '127.0.0.1:9050'   # Tor SOCKS proxy for SSL connections
        
        # Assign proxy settings to Firefox options
        options.proxy = proxy

    # Return a new Firefox driver with the specified options
    driver = webdriver.Firefox(options=options)

    return driver

# Function to run Selenium and simulate browsing
def selenium_browsing():
    driver = open_firefox_session(use_tor=True)

    # Example URL to visit (can be changed to any URL)
    driver.get("https://www.paypal.com/signin")
    time.sleep(10)  # Adjust based on loading times

    # If OTP is detected and blocked, this part won't be triggered
    try:
        otp_field = driver.find_element(By.CSS_SELECTOR, 'input[type="text"][name*="otp"]')
        print("OTP field detected. Blocking OTP request.")
    except Exception as e:
        print("OTP field not found or another error occurred:", str(e))

    # Simulate browsing other pages
    driver.get("https://www.ebay.com")
    time.sleep(5)

    driver.quit()

# Function to run everything in the background
def run_script():
    # Start mitmproxy in a separate thread
    mitmproxy_thread = Thread(target=start_mitmproxy)
    mitmproxy_thread.daemon = True
    mitmproxy_thread.start()

    # Simulate browsing with Selenium
    selenium_browsing()

# Start the script
if __name__ == "__main__":
    run_script()
