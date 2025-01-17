from datetime import timedelta
import requests
import logging
from django.conf import settings
from django.utils.timezone import now
from celery import shared_task


BASE_URL = settings.VULMATCH_SERVICE_BASE_URL
JOB_STATUS_CHECK_DELAY_SECONDS = 300

def send_request(path, body):
    url = BASE_URL + path
    logging.debug(url, path, body)
    res = requests.post(url, json=body)
    logging.debug(res.json())
    return res

@shared_task()
def cve_download_cron():
    cve_download.delay()

@shared_task()
def cve_download():
    yesterday = now() - timedelta(days=1)
    date_string = yesterday.isoformat().split('T')[0]
    res = send_request("/api/v1/cve/", {
        "last_modified_earliest": date_string,
        "last_modified_latest": date_string,
        "ignore_embedded_relationships": True
    })
    job = res.json()
    job_id = job['id']
    check_job_status.apply_async(args=[job_id], countdown=JOB_STATUS_CHECK_DELAY_SECONDS)

@shared_task()
def check_job_status(job_id):
    logging.debug(BASE_URL + f"/api/v1/jobs/{job_id}/")
    response = requests.get(BASE_URL + f"/api/v1/jobs/{job_id}/")
    job = response.json()
    logging.debug(job)
    if job['state'] == "completed":
        cwe_update.delay()
    elif  job['state'] == "pending":
        check_job_status.apply_async(args=[job_id], countdown=JOB_STATUS_CHECK_DELAY_SECONDS)
    else:
        cve_download.delay()

@shared_task()
def cwe_update():
    yesterday = now() - timedelta(days=1)
    date_string = yesterday.isoformat().split('T')[0]
    send_request("/api/v1/arango-cve-processor/cve-cwe/", {
        "ignore_embedded_relationships": True,
        "modified_min": f"{date_string}T00:00:00.000Z",
        "created_min": f"{date_string}T23:59:59.999Z"
    })
    capec_update.delay()

@shared_task()
def capec_update():
    yesterday = now() - timedelta(days=1)
    date_string = yesterday.isoformat().split('T')[0]
    send_request("/api/v1/arango-cve-processor/cve-capec/", {
        "ignore_embedded_relationships": True,
        "modified_min": f"{date_string}T00:00:00.000Z",
        "created_min": f"{date_string}T23:59:59.999Z"
    })
    attack_update.delay()

@shared_task()
def attack_update():
    yesterday = now() - timedelta(days=1)
    date_string = yesterday.isoformat().split('T')[0]
    send_request("/api/v1/arango-cve-processor/cve-attack/", {
        "ignore_embedded_relationships": True,
        "modified_min": f"{date_string}T00:00:00.000Z",
        "created_min": f"{date_string}T23:59:59.999Z"
    })
    kev_update.delay()


@shared_task()
def kev_update():
    yesterday = now() - timedelta(days=1)
    date_string = yesterday.isoformat().split('T')[0]
    send_request("/api/v1/arango-cve-processor/cve-kev/", {
        "ignore_embedded_relationships": True,
        "modified_min": f"{date_string}T00:00:00.000Z",
        "created_min": f"{date_string}T23:59:59.999Z"
    })

