# Building a Real-Time Log Anomaly Detection Platform — from laptop to autoscaling Kubernetes

*A portfolio writeup of what I built, how, and — honestly — what it does and doesn't prove.*

## The one-line version

I built a streaming security tool that ingests web-server access logs, flags
anomalous requests with an unsupervised model, and explains *why* each was flagged —
then deployed it on AWS Kubernetes (EKS) and demonstrated it **autoscaling under
load**, with the scaling captured as evidence.

It mirrors, at small scale, how systems like Microsoft Defender / Sentinel work:
ingest security telemetry at volume, detect anomalies with ML, surface and act on
them.

---

## What it does

Two ways in, one brain:

- **Upload scanner** — paste or upload an Apache/nginx access log, get back a report
  of flagged requests, each with a severity score and the specific signals that
  triggered it (e.g. *"flagged on `n_special`, `query_entropy`"*).
- **Streaming pipeline** — logs flow producer → Kafka → ingestion → inference →
  storage → API, so anomalies are scored continuously and queryable.

The detection is **unsupervised**: a small autoencoder learns what *normal* traffic
looks like and flags requests it reconstructs poorly. Labels are used only to
evaluate, never to train — the same way real security tooling catches *unknown*
threats rather than known signatures. Every request is reduced to 20 interpretable
structural features (query length, special-character density, entropy, suspicious
tokens, tool-like user agents), which keeps the model simple and, importantly,
makes every flag **explainable**.

---

## The build, in four phases

**Phase 1 — Local platform.** Parser, featurizer, autoencoder, detector, a scanner
web UI, and a four-service streaming pipeline on Apache Kafka — all containerized and
running end to end with one `docker compose up`, backed by a pytest suite (unit,
integration, end-to-end).

**Phase 2 — AWS managed services.** Pushed the image to ECR; validated each cloud
building block in isolation — Kinesis (streaming ingest), S3 (model artifact
storage), DynamoDB (verdict store), and ECS Fargate (the container running on cloud
compute, pulling the model from S3). Slimmed the image from **8.07 GB to 1.49 GB**
by switching to CPU-only PyTorch, which later paid off in fast Kubernetes pod
starts.

**Phase 3 — EKS + autoscaling.** Deployed the pipeline as pods on Amazon EKS, with
pods getting AWS access through **IRSA** (IAM Roles for Service Accounts) — no
long-lived keys baked into images. Added a **Horizontal Pod Autoscaler** on the
inference service and ran a load test to prove it scales.

**Phase 4 — Harden, document, real usage.** (In progress.)

---

## The result that matters: autoscaling under load

![HPA autoscaling under load](screenshots/hpa-autoscaling-under-load.png)

Under load, inference CPU crossed the 50% target and Kubernetes scaled the
deployment out automatically — the watch shows `cpu 1% → 97% → 123%/50%` with
`REPLICAS 1 → 2 → 3` as the load generator streamed records.

![Pods scaling, load distributed](screenshots/hpa-evidence-pods.png)

**The honest detail I keep in the writeup on purpose:** it scaled to **3** running
replicas, not the configured max of 6, because my two small worker nodes ran out of
schedulable CPU and the extra pods sat `Pending`. That's the real-world interaction
between *pod* autoscaling and *node* capacity — and the correct next layer is the
**Cluster Autoscaler**, which adds nodes when pods can't schedule. I'd rather show
that I understand that boundary than pretend at a clean 1→6.

---

## Engineering practices I'm proud of

- **Cost discipline.** The EKS control plane bills ~$73/month while it exists. Every
  cloud session followed create → use → **delete → verify-zero**, explicitly
  checking for orphaned NAT gateways, instances, and CloudFormation stacks. Total
  spend across the whole cloud build stayed within free credits.
- **Security-correct cloud auth.** IRSA instead of embedded credentials; a
  least-privilege S3 policy scoped to a single bucket.
- **Reproducibility.** Data and model are regenerated from a seeded generator and a
  training script; infrastructure is recreated from committed manifests. Tear it all
  down, rebuild it in ~25 minutes.
- **Explainability by design.** Every flagged request names the features that drove
  the score — not just a number.

---

## What this demonstrates — and what it doesn't

**Does:** real distributed-systems engineering — a streaming pipeline, decoupled
microservices, containerization, Kubernetes orchestration, horizontal autoscaling
demonstrated under load, and cloud-native security practices. This is the systems
side of a security-focused software engineering role.

**Doesn't (yet):** it is not a production system with real traffic or an SLA, and its
accuracy numbers come from **synthetic, deliberately-separable data** plus user
uploads — not a real-world benchmark. Strong scores there are not evidence of
real-world accuracy. Benchmarking against real labeled traffic (e.g. CSIC) and
driving genuine user usage are the honest next steps, not claims I make today.

That distinction — *production-grade practices, demonstrated*, versus *a deployed
commercial product* — is one I hold to deliberately.

---

## Stack

Python · PyTorch · Apache Kafka · FastAPI · Docker · **AWS (EKS, ECR, S3, DynamoDB,
Kinesis, CloudWatch)** · Kubernetes (HPA, IRSA) · eksctl · Helm · pytest

*Code and full README: [github.com/abhishekjaden/log-anomaly-platform]*
