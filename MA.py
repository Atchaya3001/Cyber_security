from flask import Flask, request, render_template, redirect, url_for, flash
import os
import subprocess
import pefile
import yara
import pyshark
import capstone
import dns.resolver
import geoip2.database
import json
import requests
import r2pipe
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Initialize Flask app
app = Flask(__name__, template_folder='/home/kali/Zero')
app.secret_key = 'your_secret_key_here'  # Ensure you set a secret key for session management

# Configure directories
app.config['UPLOAD_FOLDER'] = '/home/kali/Zero/uploads'
app.config['REPORT_FOLDER'] = '/home/kali/Zero/reports'

# Setup logging
logging.basicConfig(filename='malware_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# VirusTotal API key
VIRUSTOTAL_API_KEY = "50c331826f921e0a4d007e0450d951d8a899a3838bce7da4380b2b41182283b7"

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USERNAME = 'kousalyaprf@gmail.com'
EMAIL_PASSWORD = 'ebnetdsaqnvtyyqv '
EMAIL_FROM = 'kousalyaprf@gmail.com'

# Define the function to write reports to separate files
def write_report(content, report_name):
    report_path = os.path.join(app.config['REPORT_FOLDER'], report_name)
    with open(report_path, 'a') as report_file:
        report_file.write(content + '\n')

def is_valid_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        return True
    except (pefile.PEFormatError, FileNotFoundError):
        return False

def send_email(to_email, subject, body, attachment_path=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        if attachment_path:
            attachment = MIMEBase('application', 'octet-stream')
            with open(attachment_path, 'rb') as f:
                attachment.set_payload(f.read())
            encoders.encode_base64(attachment)
            attachment.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}'
            )
            msg.attach(attachment)

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_pe', methods=['POST'])
def analyze_pe():
    file_path = request.form['file_path']
    user_email = request.form['email']
    if not os.path.exists(file_path):
        error_message = f"File not found: {file_path}"
        logger.error(error_message)
        write_report(error_message, 'error.txt')
        return render_template('error.html', error=error_message)

    if not is_valid_pe(file_path):
        error_message = f"Invalid PE file: {file_path}"
        logger.error(error_message)
        write_report(error_message, 'error.txt')
        return render_template('error.html', error=error_message)

    try:
        pe = pefile.PE(file_path)

        # Extracting sections
        sections = [section.Name.decode().strip('\x00') for section in pe.sections]

        # Calculating entropy for each section
        entropy = [section.get_entropy() for section in pe.sections]

        # Extracting imported DLLs and functions
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                functions = [imp.name.decode() for imp in entry.imports if imp.name]
                imports.append({dll_name: functions})

        # Extracting exported functions
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name]

        report_content = (
            f"PE Analysis for {file_path}:\n"
            f"Sections: {sections}\n"
            f"Entropy: {entropy}\n"
            f"Imports: {imports}\n"
            f"Exports: {exports}\n"
        )
        report_name = f"report_PE_{os.path.basename(file_path)}.txt"
        write_report(report_content, report_name)
        
        # Send email
        send_email(user_email, 'PE Analysis Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("PE file analysis completed.")
        return render_template('result.html', result=report_content)

    except pefile.PEFormatError as e:
        logger.error(f"PEFormatError: {e}")
        write_report(f"PEFormatError: {e}", 'error.txt')
        return render_template('error.html', error=f"PEFormatError: {e}")

    except Exception as e:
        logger.error(f"Error analyzing PE file: {e}")
        write_report(f"Error analyzing PE file: {e}", 'error.txt')
        return render_template('error.html', error=str(e))
        
@app.route('/yara_scan', methods=['POST'])
def yara_scan():
    file = request.files.get('file')
    rule_path = request.form.get('rule_path')
    user_email = request.form['email']
    
    if not file:
        error_message = "No file uploaded"
        logger.error(error_message)
        write_report(error_message, 'error.txt')
        return render_template('error.html', error=error_message)

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    try:
        # Compile the YARA rules
        rules = yara.compile(filepath=rule_path)
        
        # Perform the scan and count the number of matches
        matches = rules.match(file_path)
        match_count = len(matches)
        
        # Prepare match summary details
        match_summary = [f"Number of matches: {match_count}"]
        match_summary.extend([f"Matched rule: {match.rule}" for match in matches])
        
        report_content = f"zen Scan Summary for {file_path}:\n" + "\n".join(match_summary)
        report_name = f"report_zen_{os.path.basename(file_path)}.txt"
        write_report(report_content, report_name)
        
        # Send email
        send_email(user_email, 'zen Scan Summary Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("zen scan summary completed.")
        return render_template('result.html', result=report_content)
    except Exception as e:
        logger.error(f"Error during zen scan: {e}")
        return render_template('error.html', error=str(e))
        
@app.route('/string_miner', methods=['POST'])
def string_miner():
    file_path = request.form['file_path']
    user_email = request.form['email']
    try:
        # Run the 'strings' command to extract strings from the file
        result = subprocess.run(['strings', file_path], capture_output=True, text=True)
        report_content = f"Extracted Strings from {file_path}:\n{result.stdout}\n"
        report_name = "report_string_miner.txt"
        write_report(report_content, report_name)
        
        # Send email
        send_email(user_email, 'String Miner Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("String extraction completed and email sent.")
        return render_template('result.html', result=report_content)
        
    except Exception as e:
        # Log the error and write the error report to a file
        logger.error(f"Error extracting strings: {e}")
        write_report(f"Error extracting strings: {e}", 'error.txt')
        return render_template('error.html', error=str(e))

            
def clean_hex_string(hex_str):
    # Remove any non-hexadecimal characters (e.g., spaces, newlines)
    cleaned_hex_str = re.sub(r'[^0-9a-fA-F]', '', hex_str)
    # Ensure the length is even (each byte is represented by two hex characters)
    if len(cleaned_hex_str) % 2 != 0:
        cleaned_hex_str = '0' + cleaned_hex_str
    return cleaned_hex_str
@app.route('/disassemble_code', methods=['POST'])
def disassemble_code():
    code_hex = request.form['code']
    user_email = request.form['email']
    
    try:
        # Sanitize the input to remove any non-hexadecimal characters
        sanitized_code_hex = ''.join(c for c in code_hex if c in '0123456789abcdefABCDEF')
        
        # Ensure the length of the string is even (since each byte is represented by two hex digits)
        if len(sanitized_code_hex) % 2 != 0:
            raise ValueError("The hexadecimal string has an incomplete byte.")
        
        # Convert the sanitized hexadecimal string to bytes
        byte_data = bytes.fromhex(sanitized_code_hex)
        
        # Create a memoryview of the byte data
        mv = memoryview(byte_data)
        
        # Initialize the disassembler
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        # Disassemble the code using the memoryview
        disassembly = '\n'.join(
            f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}" for ins in md.disasm(mv, 0x1000)
        )
        
        # Prepare the report content
        report_content = f"Code Disassembly:\n\n{disassembly}\n\n"
        report_name = "report_Disassembly.txt"
        
        # Write the disassembly report
        write_report(report_content, report_name)
        
        # Send the disassembly report via email
        send_email(user_email, 'Code Disassembly Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("Code disassembly completed.")
        return render_template('result.html', result=report_content)

    except Exception as e:
        logger.error(f"Error during code disassembly: {e}")
        return render_template('error.html',error=str(e))


    except Exception as e:
        logger.error(f"Error during code disassembly: {e}")
        return render_template('error.html',error=str(e))


@app.route('/analyze_with_radare2', methods=['POST'])
def analyze_with_graphinsight():
    file_path = request.form['file_path']
    user_email = request.form['email']
    try:
        r2 = r2pipe.open(file_path)
        r2.cmd('aaa')  # Analyze
        analysis_output = r2.cmd('afl')  # List functions

        # Generate the analysis report
        report_name = f"report_Radare2_{os.path.basename(file_path)}.txt"
        write_report(analysis_output, report_name)

        # Generate the control flow graph in DOT format
        cfg_dot_output = r2.cmd('agCd')  # Generate CFG in DOT format
        cfg_dot_report_name = f"cfg_{os.path.basename(file_path)}.dot"
        cfg_dot_report_path = os.path.join(app.config['REPORT_FOLDER'], cfg_dot_report_name)
        write_report(cfg_dot_output, cfg_dot_report_name)

        # Convert the DOT file to PNG using the dot command from Graphviz
        cfg_png_report_name = f"cfg_{os.path.basename(file_path)}.png"
        cfg_png_report_path = os.path.join(app.config['REPORT_FOLDER'], cfg_png_report_name)
        
        subprocess.run(['dot', '-Tpng', cfg_dot_report_path, '-o', cfg_png_report_path], check=True)
        
        # Send the analysis report via email
        send_email(user_email, 'Radare2 Analysis Report', analysis_output, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        # Optionally, send the CFG report and PNG via email as well
        send_email(user_email, 'Radare2 CFG Report', cfg_dot_output, cfg_dot_report_path)
        send_email(user_email, 'Radare2 CFG Image', "Please find the CFG image attached.", cfg_png_report_path)

        logger.info("Radare2 analysis, CFG generation, and PNG conversion completed.")
        return render_template('result.html', result=analysis_output)

    except Exception as e:
        logger.error(f"Error during Radare2 analysis: {e}")
        return render_template('error.html', error=str(e))

@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    domain = request.form['domain']
    user_email = request.form['email']
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [answer.address for answer in answers]
        report_content = f"DNS Lookup for {domain}:\nIP Addresses: {', '.join(ip_addresses)}\n"
        report_name = f"report_DNS_{domain}.txt"
        write_report(report_content, report_name)
        
        # Send email
        send_email(user_email, 'DNS Lookup Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("DNS lookup completed.")
        return render_template('result.html', result=report_content)

    except Exception as e:
        logger.error(f"Error during DNS lookup: {e}")
        return render_template('error.html', error=str(e))

@app.route('/geoip_lookup', methods=['POST'])
def geoip_country_lookup():
    ip_address = request.form['ip_address']
    user_email = request.form['email']
    try:
        reader = geoip2.database.Reader('/home/kali/Zero/GeoLite2-Country.mmdb')
        response = reader.country(ip_address)
        country = response.country.name
        report_content = f"GeoIP Lookup for {ip_address}:\nCountry: {country}\n"
        report_name = f"report_GeoIP_Country_{ip_address}.txt"
        write_report(report_content, report_name)
        
        # Send email
        send_email(user_email, 'GeoIP Country Lookup Report', report_content, os.path.join(app.config['REPORT_FOLDER'], report_name))
        
        logger.info("GeoIP country lookup completed.")
        return render_template('result.html', result=report_content)

    except Exception as e:
        logger.error(f"Error during GeoIP lookup: {e}")
        return render_template('error.html', error=str(e))

@app.route('/Threat_scan', methods=['POST'])
def Threat_scan():
    vt_type = request.form.get('vt_type')
    vt_value = request.form.get('vt_value')
    user_email = request.form.get('email')
    vt_file = request.files.get('vt_file')

    try:
        # Validate input
        if not vt_type or not user_email or (vt_type == 'file' and not vt_file) or (vt_type != 'file' and not vt_value):
            raise ValueError("All fields (scan type, value or file, and email) must be provided.")

        # Construct Threatscan API URL
        if vt_type == "file_hash":
            url = f"https://www.virustotal.com/api/v3/files/{vt_value}"
        elif vt_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{vt_value}"
        elif vt_type == "ip-address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{vt_value}"
        elif vt_type == "url":
            # URL needs to be URL encoded and in a specific format
            encoded_url = base64.urlsafe_b64encode(vt_value.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        elif vt_type == "file" and vt_file:
            # Handle file upload
            files = {'file': (vt_file.filename, vt_file.stream, vt_file.content_type)}
            url = "https://www.virustotal.com/api/v3/files"
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.post(url, headers=headers, files=files)
        else:
            raise ValueError("Invalid scan type provided.")

        # If not a file scan, proceed with the GET request
        if vt_type != "file":
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.get(url, headers=headers)

        # Check for successful response
        if response.status_code == 404:
            raise Exception(f"The {vt_type} '{vt_value}' was not found in VirusTotal's database.")
        elif response.status_code != 200:
            raise Exception(f"Failed to retrieve data from VirusTotal API. Status code: {response.status_code}")

        # Parse response data
        response_data = response.json()
        if not response_data:
            raise ValueError("Received empty response from VirusTotal API.")

        # Check for error in the response
        if 'error' in response_data:
            error_message = response_data['error'].get('message', 'Unknown error occurred.')
            raise Exception(f"VirusTotal error: {error_message}")

        # Create the report content
        report_content = f"Threat Scan Results for {vt_value or vt_file.filename}:\n{json.dumps(response_data, indent=2)}\n"
        report_name = f"report_Threatscan_{vt_type}_{vt_value or vt_file.filename}.txt"

        # Save the report
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_name)
        write_report(report_content, report_path)

        # Send the report via email
        send_email(user_email, 'Threat Scan Report', report_content, report_path)

        logger.info("Threat scan completed successfully.")
        return render_template('result.html', result=report_content)

    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return render_template('error.html', error=str(ve))

    except requests.exceptions.RequestException as re:
        logger.error(f"Request error: {re}")
        return render_template('error.html', error=f"Request failed: {re}")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return render_template('error.html', error=str(e))


if __name__ == '__main__':
    # Ensure upload and report directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

    port = int(input("Enter the port number to run the application: "))
    app.run(debug=True, port=port)


