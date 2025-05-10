from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_area4_seongbuk():
    # 성북구의 우편번호 02842 사용
    response = client.get("/api/get_user_area", params={"zip_code": 2842})
    assert response.status_code == 200
    data = response.json()
    assert data["area"] == "area4"
    assert data["gu"] == "성북구"
    print("성북구 테스트 통과:", data)
