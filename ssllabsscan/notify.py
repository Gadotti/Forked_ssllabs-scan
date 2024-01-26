import requests

DISCORD_WEBHOOK_URL = "[webhook_url]"

def notify(host: str):
    content = f"SSLlabs Scan: The host '{host}' did not meet the quality parameters, please check."    
    print(content)
    discord_notification(content)

def notify_exception(host: str, error: str):
    content = f"SSLlabs Scan [EXCEPTION]: Host - '{host}'. Error: {error}"
    print(content)
    discord_notification(content)

def discord_notification(content: str):
    if (DISCORD_WEBHOOK_URL == "[webhook_url]"):
        return
    
    try:
        # Payload to send to Discord
        payload = {"content": content}

        # Make a POST request to the webhook URL
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)

        # Check if the request was successful (status code 2xx)
        response.raise_for_status()

        print("Notification sent successfully.")
        return True

    except requests.exceptions.RequestException as e:
        print(f"Failed to send notification: {e}")
        return False