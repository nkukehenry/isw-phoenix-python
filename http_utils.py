import requests
import logging

class HttpUtil:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def post_http_request(self, resource_url, headers, data):
        self.logger.info(f"http outgoing request body {data}")
        self.logger.info(f"http outgoing request url {resource_url}")

        response = requests.post(
            resource_url,
            data=data,
            headers=headers,
            verify=False  # Disables SSL certificate verification (not recommended for production)
        )

        response_code = response.status_code
        response_text = response.text

        self.logger.info(f"http response code {response_code}")
        self.logger.info(f"http response body {response_text}")

        return response_text

    def get_http_request(self, resource_url, headers):
        self.logger.info(f"http outgoing request url {resource_url}")

        response = requests.get(
            resource_url,
            headers=headers,
            verify=False  # Disables SSL certificate verification (not recommended for production)
        )

        response_code = response.status_code
        response_text = response.text

        self.logger.info(f"http response code {response_code}")
        self.logger.info(f"http response body {response_text}")

        return response_text
