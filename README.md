## Install

1. สร้างไฟล์ `.env` สำหรับตั้งค่า environment variables

```env
DISCORD_TOKEN=your_discord_bot_token
OWNER_ID=123456789012345678
```

2. สร้าง Docker image

```bash
docker build -t 12oi3jo12rjo1sa .
```

3. รัน Docker container

```bash
docker-compose up -d
```

4. ตรวจสอบสถานะ container

```bash
docker ps
```

## หมายเหตุ

- ฟีเจอร์บางอย่างต้องใช้ network access และอาจขึ้นกับ API ภายนอก
- สำหรับคำสั่งที่ใช้ `ciphey` ต้องติดตั้ง `ciphey` ด้วยตัวเอง