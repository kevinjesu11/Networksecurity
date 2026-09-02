
import shutil
import subprocess

from networksecurity.logging.logger import logging


class S3Sync:
    def sync_folder_to_s3(self,folder,aws_bucket_url):
        if not shutil.which("aws"):
            logging.info("AWS CLI is not installed. Skipping S3 upload.")
            return

        if not folder or not aws_bucket_url:
            logging.info("S3 sync source or destination is missing. Skipping S3 upload.")
            return

        subprocess.run(["aws", "s3", "sync", folder, aws_bucket_url], check=True)

    def sync_folder_from_s3(self,folder,aws_bucket_url):
        if not shutil.which("aws"):
            logging.info("AWS CLI is not installed. Skipping S3 download.")
            return

        if not folder or not aws_bucket_url:
            logging.info("S3 sync source or destination is missing. Skipping S3 download.")
            return

        subprocess.run(["aws", "s3", "sync", aws_bucket_url, folder], check=True)
