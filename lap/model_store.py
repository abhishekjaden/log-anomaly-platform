#!/usr/bin/env python3
"""
lap.model_store — resolve the detector model from S3 or a local path.

Lets cloud services (ECS/EKS) pull ml/models/detector.pt from S3 at startup instead
of baking it into the image, while local dev still uses the on-disk file. Controlled
by env vars:
    MODEL_S3_URI   e.g. s3://lap-artifacts-<acct>/models/detector.pt   (optional)
    MODEL_PATH     local fallback path (default ml/models/detector.pt)
"""
from __future__ import annotations

import os


def resolve_model_path() -> str:
    """Return a local filesystem path to the model, downloading from S3 if configured.
    If MODEL_S3_URI is set, fetch it to a local cache path and return that; otherwise
    return the local MODEL_PATH unchanged."""
    local_path = os.environ.get("MODEL_PATH", "ml/models/detector.pt")
    s3_uri = os.environ.get("MODEL_S3_URI")
    if not s3_uri:
        return local_path

    # lazy import so local/dev usage doesn't require boto3
    import boto3

    assert s3_uri.startswith("s3://"), f"MODEL_S3_URI must be s3://..., got {s3_uri}"
    bucket, _, key = s3_uri[len("s3://"):].partition("/")
    cache_path = os.environ.get("MODEL_CACHE", "/tmp/detector.pt")
    os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)

    region = os.environ.get("AWS_REGION", "ap-south-1")
    boto3.client("s3", region_name=region).download_file(bucket, key, cache_path)
    return cache_path


if __name__ == "__main__":
    print("resolved model path:", resolve_model_path())