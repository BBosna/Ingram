import os
import requests
from collections import namedtuple
import time

from loguru import logger


class POCTemplate:

    level = namedtuple("level", "high medium low")("高", "中", "低")
    poc_classes = []

    @staticmethod
    def register_poc(self):
        self.poc_classes.append(self)

    def __init__(self, config):
        self.config = config
        # poc 名称 (直接用文件名或者另取一个名字)
        self.name = self.get_file_name(__file__)
        # poc 所针对的应用
        self.product = "base"
        # 应用版本
        self.product_version = ""
        # 引用的 url
        self.ref = ""
        # 漏洞等级
        self.level = self.level.low
        # 描述
        self.desc = """"""

    def get_file_name(self, file):
        return os.path.basename(file).split(".")[0]

    def verify(self, ip, port):
        """用来验证是否存在该漏洞
        params:
        - ip: ip 地址, str
        - port: 端口号, str or num

        return:
        - 验证成功的形式为 (ip, port, self.product, user, password, self.name)
        - 验证失败��形式为 None
        """
        pass

    def _snapshot(self, url, img_file_name, auth=None, min_size=1024) -> int:
        """
        Snapshot alma işlemi
        """
        img_path = os.path.join(
            self.config.out_dir, self.config.snapshots, img_file_name
        )
        headers = {"Connection": "close", "User-Agent": self.config.user_agent}
        max_retries = 3

        device_info = f"Device: {self.product}, URL: {url}"

        for attempt in range(max_retries):
            try:
                if auth:
                    res = requests.get(
                        url,
                        auth=auth,
                        timeout=self.config.timeout,
                        verify=False,
                        headers=headers,
                        stream=True,
                    )
                else:
                    res = requests.get(
                        url,
                        timeout=self.config.timeout,
                        verify=False,
                        headers=headers,
                        stream=True,
                    )

                if res.status_code == 200 and "head" not in res.text:
                    # Başarılı durum - değişiklik yok
                    content = b""
                    for chunk in res.iter_content(10240):
                        content += chunk

                    if len(content) >= min_size:
                        with open(img_path, "wb") as f:
                            f.write(content)
                        logger.success(
                            f"Snapshot saved successfully: {img_file_name} ({len(content)} bytes) - {device_info}"
                        )
                        return 1
                    else:
                        logger.warning(
                            f"Snapshot too small: {img_file_name} ({len(content)} bytes), retrying... ({attempt+1}/{max_retries}) - {device_info}"
                        )
                        continue

                else:
                    # Hata detaylarını topla
                    error_detail = {
                        "status_code": res.status_code,
                        "content_type": res.headers.get("Content-Type", "N/A"),
                        "server": res.headers.get("Server", "N/A"),
                        "response_text": (
                            res.text[:200] if res.text else "Empty response"
                        ),
                    }

                    logger.warning(
                        f"Invalid response for {img_file_name}, attempt {attempt+1}/{max_retries}\n"
                        f"Details: {error_detail}\n"
                        f"Device Info: {device_info}"
                    )

            except requests.exceptions.Timeout:
                logger.error(
                    f"Timeout error for {img_file_name}, attempt {attempt+1}/{max_retries}\n"
                    f"Device Info: {device_info}"
                )
            except requests.exceptions.ConnectionError as e:
                logger.error(
                    f"Connection error for {img_file_name}, attempt {attempt+1}/{max_retries}\n"
                    f"Error: {str(e)}\n"
                    f"Device Info: {device_info}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error for {img_file_name}, attempt {attempt+1}/{max_retries}\n"
                    f"Error: {str(e)}\n"
                    f"Device Info: {device_info}"
                )

            # Her denemeden önce kısa bir bekleme
            if attempt < max_retries - 1:
                time.sleep(2)

        logger.error(
            f"Failed to get snapshot after {max_retries} attempts: {img_file_name} - {device_info}"
        )
        return 0

    def exploit(self, results: tuple) -> int:
        """利用, 主要是获取 snapshot
        params:
        - results: self.verify 验证成功时的返回结果
        return:
        - 返回一个数, 代表获取了几张截图, 一般为 1 或 0
        """
        url = ""
        img_file_name = ""
        return self._snapshot(url, img_file_name)
