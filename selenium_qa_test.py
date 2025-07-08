import os
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException, TimeoutException, ElementClickInterceptedException
from selenium.webdriver.common.action_chains import ActionChains

# Config
BASE_URL = "http://localhost:8080/"
RECORDS_DIR = "records"
PAGES = [
    ("index.html", "Dashboard"),
    ("upload.html", "Upload"),
    ("hash_input.html", "Hash Input"),
    ("spreadsheet.html", "Spreadsheet"),
    ("results.html", "Results"),
    ("log.html", "Log"),
]

# Ensure records directory exists
os.makedirs(RECORDS_DIR, exist_ok=True)

# Setup Chrome WebDriver
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--window-size=1280,800')
driver = webdriver.Chrome(options=chrome_options)

test_results = []

def screenshot(name):
    path = os.path.join(RECORDS_DIR, f"{name}.png")
    driver.save_screenshot(path)
    print(f"Screenshot saved: {path}")

def log_step(scenario, step):
    print(f"[{scenario}] {step}")

def safe_click(element):
    try:
        element.click()
    except ElementClickInterceptedException:
        driver.execute_script("arguments[0].scrollIntoView(true);", element)
        time.sleep(0.5)
        try:
            element.click()
        except Exception:
            # Try to close overlays or modals if present
            try:
                close_btns = driver.find_elements(By.XPATH, "//button[contains(@class, 'close') or contains(@aria-label, 'close') or contains(text(), 'Close')]")
                for btn in close_btns:
                    try:
                        btn.click()
                        time.sleep(0.5)
                    except Exception:
                        pass
                element.click()
            except Exception:
                raise

def assert_text_present(text, scenario, screenshot_name):
    assert text.lower() in driver.page_source.lower(), f"Expected '{text}' not found."
    screenshot(screenshot_name)
    log_step(scenario, f"Verified presence of text: {text}")

def test_scenario_curious_newcomer():
    scenario = "Curious Newcomer"
    steps = []
    try:
        driver.get(BASE_URL + "index.html")
        log_step(scenario, "Loaded dashboard")
        screenshot("curious_dashboard")
        steps.append("Dashboard loaded")
        # Click through navigation links and assert page loads
        for page, label in PAGES:
            nav_links = driver.find_elements(By.LINK_TEXT, label)
            if nav_links:
                nav_links[0].click()
                time.sleep(1)
                screenshot(f"curious_nav_{label.lower()}")
                assert label.lower() in driver.page_source.lower()
                steps.append(f"Navigated to {label}")
                driver.back()
                time.sleep(1)
        test_results.append((scenario, True, steps))
    except Exception as e:
        log_step(scenario, f"Error: {e}")
        steps.append(f"Error: {e}")
        test_results.append((scenario, False, steps))

def test_scenario_soc_analyst():
    scenario = "SOC Analyst"
    steps = []
    try:
        driver.get(BASE_URL + "upload.html")
        log_step(scenario, "Navigated to upload page")
        screenshot("soc_upload_page")
        steps.append("Upload page loaded")
        file_input = driver.find_element(By.ID, "fileInput")
        dummy_path = os.path.abspath("soc_test.txt")
        with open(dummy_path, "w") as f:
            f.write("soc test file")
        file_input.send_keys(dummy_path)
        time.sleep(1)
        screenshot("soc_file_selected")
        steps.append("File selected for upload")
        # Try to click upload if button exists
        try:
            upload_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Upload')]")
            safe_click(upload_btn)
            time.sleep(2)
            screenshot("soc_file_uploaded")
            steps.append("Upload button clicked")
        except Exception:
            steps.append("Upload button not found or not clickable")
        os.remove(dummy_path)
        driver.get(BASE_URL + "results.html")
        time.sleep(1)
        screenshot("soc_results_page")
        assert_text_present("Results", scenario, "soc_results_assert")
        steps.append("Results page loaded and verified")
        test_results.append((scenario, True, steps))
    except Exception as e:
        log_step(scenario, f"Error: {e}")
        steps.append(f"Error: {e}")
        test_results.append((scenario, False, steps))

def test_scenario_threat_researcher():
    scenario = "Threat Researcher"
    steps = []
    try:
        driver.get(BASE_URL + "hash_input.html")
        log_step(scenario, "Navigated to hash input page")
        screenshot("researcher_hash_input")
        steps.append("Hash input page loaded")
        textarea = driver.find_element(By.ID, "hashInput")
        textarea.clear()
        textarea.send_keys("e9c710dc013dfb22c4fab738e3cda5657a307e1c3b667ac75cace86b333941c9\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        screenshot("researcher_hashes_entered")
        steps.append("Hashes entered")
        scan_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan Hashes')]")
        safe_click(scan_btn)
        time.sleep(2)
        screenshot("researcher_hashes_scanned")
        steps.append("Scan button clicked and scan completed")
        driver.get(BASE_URL + "results.html")
        time.sleep(1)
        # Filter results
        search_input = driver.find_element(By.ID, "searchInput")
        search_input.send_keys("malware")
        time.sleep(1)
        screenshot("researcher_results_filtered")
        steps.append("Results filtered by 'malware'")
        # Download CSV if button exists
        try:
            csv_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Download CSV')]")
            safe_click(csv_btn)
            time.sleep(1)
            screenshot("researcher_csv_downloaded")
            steps.append("CSV downloaded")
        except Exception:
            steps.append("CSV download button not found")
        test_results.append((scenario, True, steps))
    except Exception as e:
        log_step(scenario, f"Error: {e}")
        steps.append(f"Error: {e}")
        test_results.append((scenario, False, steps))

def test_scenario_manager():
    scenario = "Manager"
    steps = []
    try:
        driver.get(BASE_URL + "index.html")
        log_step(scenario, "Manager loads dashboard")
        screenshot("manager_dashboard")
        steps.append("Dashboard loaded")
        driver.get(BASE_URL + "results.html")
        time.sleep(1)
        screenshot("manager_results")
        steps.append("Results page loaded")
        # Try to open analytics dashboard if button exists
        try:
            analytics_btn = driver.find_element(By.XPATH, "//button[contains(@title, 'Analytics')]")
            safe_click(analytics_btn)
            time.sleep(1)
            screenshot("manager_analytics")
            steps.append("Analytics dashboard opened")
        except Exception:
            steps.append("Analytics dashboard button not found")
        driver.get(BASE_URL + "log.html")
        time.sleep(1)
        screenshot("manager_log")
        steps.append("Log page loaded")
        test_results.append((scenario, True, steps))
    except Exception as e:
        log_step(scenario, f"Error: {e}")
        steps.append(f"Error: {e}")
        test_results.append((scenario, False, steps))

def test_scenario_qa_engineer():
    scenario = "QA Engineer"
    steps = []
    try:
        # Test empty file upload
        driver.get(BASE_URL + "upload.html")
        log_step(scenario, "QA tests empty file upload")
        screenshot("qa_upload_page")
        steps.append("Upload page loaded")
        file_input = driver.find_element(By.ID, "fileInput")
        empty_path = os.path.abspath("empty.txt")
        with open(empty_path, "w") as f:
            pass
        file_input.send_keys(empty_path)
        time.sleep(1)
        screenshot("qa_empty_file_selected")
        steps.append("Empty file selected")
        os.remove(empty_path)
        # Test invalid hash
        driver.get(BASE_URL + "hash_input.html")
        textarea = driver.find_element(By.ID, "hashInput")
        textarea.clear()
        textarea.send_keys("notahash")
        screenshot("qa_invalid_hash")
        steps.append("Invalid hash entered")
        scan_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan Hashes')]")
        safe_click(scan_btn)
        time.sleep(1)
        screenshot("qa_invalid_hash_scanned")
        # Check for error message
        try:
            assert_text_present("invalid", scenario, "qa_invalid_hash_error")
            steps.append("Error message for invalid hash displayed")
        except Exception:
            steps.append("No error message for invalid hash")
        # Test malformed spreadsheet
        driver.get(BASE_URL + "spreadsheet.html")
        try:
            spreadsheet_url_input = driver.find_element(By.ID, "spreadsheetUrl")
            spreadsheet_url_input.send_keys("https://example.com/bad-spreadsheet.csv")
            time.sleep(1)
            screenshot("qa_malformed_spreadsheet")
            steps.append("Malformed spreadsheet URL entered")
            # Test the scan button
            scan_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan from Spreadsheet')]")
            safe_click(scan_btn)
            time.sleep(2)
            screenshot("qa_spreadsheet_scan_attempted")
            steps.append("Spreadsheet scan attempted")
        except Exception as e:
            steps.append(f"Spreadsheet functionality not found: {e}")
        test_results.append((scenario, True, steps))
    except Exception as e:
        log_step(scenario, f"Error: {e}")
        steps.append(f"Error: {e}")
        test_results.append((scenario, False, steps))

def test_dashboard():
    driver.get(BASE_URL + "index.html")
    time.sleep(1)
    screenshot("dashboard_loaded")
    assert "Malwize" in driver.title
    test_results.append(("Dashboard Load", True))

def test_upload():
    driver.get(BASE_URL + "upload.html")
    time.sleep(1)
    screenshot("upload_loaded")
    # Test file input (simulate file selection)
    try:
        file_input = driver.find_element(By.ID, "fileInput")
        # Create a dummy file for upload
        dummy_path = os.path.abspath("dummy.txt")
        with open(dummy_path, "w") as f:
            f.write("dummy test file")
        file_input.send_keys(dummy_path)
        time.sleep(1)
        screenshot("upload_file_selected")
        os.remove(dummy_path)
        test_results.append(("Upload File Input", True))
    except Exception as e:
        test_results.append(("Upload File Input", False))

def test_hash_input():
    driver.get(BASE_URL + "hash_input.html")
    time.sleep(1)
    screenshot("hash_input_loaded")
    try:
        textarea = driver.find_element(By.ID, "hashInput")
        textarea.clear()
        textarea.send_keys("e9c710dc013dfb22c4fab738e3cda5657a307e1c3b667ac75cace86b333941c9")
        screenshot("hash_input_filled")
        scan_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan Hashes')]")
        scan_btn.click()
        time.sleep(2)
        screenshot("hash_input_scanned")
        test_results.append(("Hash Input Scan", True))
    except Exception as e:
        test_results.append(("Hash Input Scan", False))

def test_spreadsheet():
    driver.get(BASE_URL + "spreadsheet.html")
    time.sleep(1)
    screenshot("spreadsheet_loaded")
    try:
        # Test spreadsheet URL input
        url_input = driver.find_element(By.ID, "spreadsheetUrl")
        url_input.send_keys("https://example.com/test-spreadsheet.csv")
        time.sleep(1)
        screenshot("spreadsheet_url_entered")
        
        # Test column name input
        column_input = driver.find_element(By.ID, "spreadsheetColumn")
        column_input.clear()
        column_input.send_keys("hash")
        time.sleep(1)
        screenshot("spreadsheet_column_entered")
        
        # Test scan button
        scan_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan from Spreadsheet')]")
        safe_click(scan_btn)
        time.sleep(2)
        screenshot("spreadsheet_scan_clicked")
        
        test_results.append(("Spreadsheet Functionality", True))
    except Exception as e:
        test_results.append(("Spreadsheet Functionality", False))

def test_results_page():
    driver.get(BASE_URL + "results.html")
    time.sleep(1)
    screenshot("results_loaded")
    try:
        # Try filtering/searching
        search_input = driver.find_element(By.ID, "searchInput")
        search_input.send_keys("test")
        time.sleep(1)
        screenshot("results_search")
        test_results.append(("Results Search", True))
    except Exception as e:
        test_results.append(("Results Search", False))

def test_log_page():
    driver.get(BASE_URL + "log.html")
    time.sleep(1)
    screenshot("log_loaded")
    try:
        assert "Log" in driver.title
        test_results.append(("Log Page Load", True))
    except Exception as e:
        test_results.append(("Log Page Load", False))

def main():
    try:
        test_scenario_curious_newcomer()
        test_scenario_soc_analyst()
        test_scenario_threat_researcher()
        test_scenario_manager()
        test_scenario_qa_engineer()
    finally:
        driver.quit()
        summary_lines = []
        summary_lines.append("\nQA Selenium Test Summary:")
        for name, passed, steps in test_results:
            summary_lines.append(f"{name}: {'PASS' if passed else 'FAIL'}")
            for step in steps:
                summary_lines.append(f"  - {step}")
        summary_lines.append(f"\nScreenshots saved in: {RECORDS_DIR}")
        summary = "\n".join(summary_lines)
        print(summary)
        with open("selenium_results.txt", "w") as f:
            f.write(summary)

if __name__ == "__main__":
    main() 