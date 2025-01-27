from seleniumwire import webdriver  # Import from selenium-wire to enable interception
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.proxy import Proxy, ProxyType


def open_firefox_session(use_tor=False):
    """
    Launches a Firefox session with or without the Tor proxy.
    """
    firefox_options = FirefoxOptions()
    firefox_options.add_argument("--headless")  # Run in headless mode (no GUI)

    # Configure the Selenium Wire proxy
    seleniumwire_options = {}

    if use_tor:
        seleniumwire_options['proxy'] = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }

    # Launch the Selenium Wire WebDriver with proxy settings
    driver = webdriver.Firefox(options=firefox_options, seleniumwire_options=seleniumwire_options)
    return driver


def intercept_and_extract_otp(driver):
    """
    Intercepts network requests and extracts OTP/2FA tokens.
    """
    try:
        for request in driver.requests:  # Access intercepted requests
            if request.response and "otp" in request.url.lower():  # Look for 'otp' in URL
                print(f"Intercepted OTP Request: {request.url}")
                print(f"Response Body: {request.response.body.decode('utf-8')}")
    except Exception as e:
        print(f"Error during interception: {e}")


def selenium_browsing():
    """
    Opens a webpage using Selenium and extracts OTP/2FA tokens from intercepted requests.
    """
    driver = open_firefox_session(use_tor=True)
    try:
        # Example: Access a login page that generates an OTP request
        driver.get("https://example.com/login")  # Replace with the real target URL
        print("Page title:", driver.title)

        # Intercept and extract OTP requests
        intercept_and_extract_otp(driver)
    except Exception as e:
        print(f"Error during browsing: {e}")
    finally:
        driver.quit()


if __name__ == "__main__":
    selenium_browsing()
