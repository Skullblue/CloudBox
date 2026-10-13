FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      util-linux mount ntfs-3g exfatprogs dosfstools e2fsprogs xfsprogs udev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py reset_password.py ./
COPY static ./static

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
