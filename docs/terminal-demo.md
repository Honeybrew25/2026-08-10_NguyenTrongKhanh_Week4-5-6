# Demo thực thi thật trên terminal

> Xem [README](../README.md) để cài môi trường trước khi chạy.

Terminal hiển thị từng bước để người xem dễ theo dõi. Nó không thay đổi quy
tắc an toàn hoặc tự phê duyệt yêu cầu. API key chỉ được đọc từ môi trường và
không được in ra màn hình.

## Khởi động

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
python -m project_sentinel demo --provider deterministic --execute --format human
```

Chỉ dùng `--verbose` khi cần xem mã của quy tắc và yêu cầu.

Mỗi tình huống có tám bước: nhận kết quả quét, chuẩn hóa, phân tích, tạo đề
xuất, phê duyệt, gửi qua cổng Envoy, kiểm tra phản hồi và tạo báo cáo.

## Chọn bốn hoặc tám tình huống

Lệnh ở phần khởi động dùng bộ mặc định gồm bốn tình huống đã có bằng chứng:
Reject, Approve, phản hồi đáng ngờ và đường dẫn quản trị bị chặn.

Chạy bộ mở rộng:

```bash
python -m project_sentinel demo --provider deterministic --execute --scenario-set extended --format human
```

Bộ này có tám tình huống. Bốn tình huống thêm vào là:

1. `GET /api/test/status` trả kết quả bình thường.
2. `POST /api/test/validate` dùng `wrong-type`; HTTP 422 là kết quả mong đợi.
3. `wrong-type` bị từ chối khi ghép với endpoint trạng thái.
4. Proposal yêu cầu header `Authorization` bị policy từ chối.

Terminal sẽ hỏi ba lần. Nhập theo thứ tự `Reject`, `Approve`, `Approve`. Lần
Approve cuối dành cho tình huống `wrong-type`. Hai tình huống bị policy từ chối
không mở bước phê duyệt và không gửi request.

Nếu demo chưa đạt, terminal sẽ ghi rõ tình huống bị lệch, kết quả mong đợi,
kết quả thực tế và cách chạy lại.

Khi demo kết thúc, terminal in sẵn lệnh đầy đủ với đường dẫn tương đối.

```bash
python scripts/build_dashboard_replay.py "<demo-summary>"
```

Lệnh này chỉ nhận bản tổng kết `extended` đủ tám tình huống rồi cập nhật dữ
liệu phát lại đã làm sạch. Khi thành công, terminal sẽ báo `DASHBOARD ĐÃ CẬP
NHẬT`, tên demo, số tình huống, hai file đã thay đổi và lệnh mở lại giao diện.

Nếu giao diện đang chạy trong Docker, build lại container rồi nhấn `Ctrl+F5`:

```bash
docker compose up --build --detach --wait --wait-timeout 180
```

## Chọn kiểu hiển thị

`--format auto` tự chọn kiểu phù hợp: terminal dùng bản dễ đọc, còn kết quả
chuyển sang tệp dùng JSON. Có thể chọn trực tiếp:

```bash
# Trình bày trực tiếp
python -m project_sentinel demo --provider deterministic --execute --format human

# Dùng trong script hoặc CI
python -m project_sentinel demo --provider deterministic --format json
```

## Nếu cổng Envoy chưa sẵn sàng

Mã `gateway_preflight_timeout` có nghĩa là hệ thống chưa gửi yêu cầu kiểm thử.
Kiểm tra theo thứ tự sau:

```bash
docker compose ps
curl http://127.0.0.1:8080/health
docker compose logs --no-color --tail 200 envoy authz-service api
```

`/health` phải trả về HTTP `200`. Nếu vừa mở Docker, chờ các dịch vụ chuyển
sang `healthy`, rồi chạy lại:

```bash
python -m project_sentinel preflight --execute
```

## Kết thúc

```bash
docker compose down --remove-orphans
docker compose ps --all
```
