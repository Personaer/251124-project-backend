# OAuth2 인증 플로우 및 시스템 구조

## 목차
1. [시스템 개요](#시스템-개요)
2. [패키지 구조](#패키지-구조)
3. [OAuth2 인증 플로우](#oauth2-인증-플로우)
4. [API 엔드포인트](#api-엔드포인트)
5. [주요 컴포넌트](#주요-컴포넌트)
6. [환경 설정](#환경-설정)
7. [데이터 흐름](#데이터-흐름)

---

## 시스템 개요

이 프로젝트는 Spring Boot 기반의 마이크로서비스 아키텍처로, OAuth2를 통한 소셜 로그인(카카오, 네이버, 구글)을 지원합니다.

### 아키텍처
```
Frontend (localhost:3000)
    ↓
Gateway (localhost:8080)
    ↓
Auth Service (localhost:8081)
    ↓
OAuth Provider (Kakao/Naver/Google)
```

---

## 패키지 구조

```
authservice/
├── auth/                          # OAuth2 통합 콜백 컨트롤러
│   └── OAuth2CallbackController.java
├── google/                        # 구글 OAuth 관련
│   ├── GoogleController.java
│   ├── GoogleOAuthService.java
│   ├── GoogleTokenResponse.java
│   └── GoogleUserInfo.java
├── kakao/                         # 카카오 OAuth 관련
│   ├── KakaoController.java
│   ├── KakaoOAuthService.java
│   ├── KakaoTokenResponse.java
│   └── KakaoUserInfo.java
├── naver/                         # 네이버 OAuth 관련
│   ├── NaverController.java
│   ├── NaverOAuthService.java
│   ├── NaverTokenResponse.java
│   └── NaverUserInfo.java
├── response/                      # 공통 응답 DTO
│   ├── ApiResponse.java
│   ├── LoginResponse.java
│   └── UserInfoResponse.java
├── util/                          # 유틸리티
│   └── JwtService.java
├── config/                        # 설정
│   └── JwtProperties.java
└── AuthServiceApplication.java
```

### 패키지 구조 전략
- **제공자별 패키지**: 각 OAuth 제공자(google, kakao, naver)별로 Controller, Service, DTO를 한 폴더에 모아놓아 응집도를 높임
- **공통 컴포넌트**: response, util, config는 공통으로 사용되는 컴포넌트
- **통합 콜백**: OAuth2CallbackController는 모든 제공자의 콜백을 처리하는 통합 컨트롤러

---

## OAuth2 인증 플로우

### 전체 플로우 다이어그램

```
[Frontend]                    [Gateway]              [Auth Service]              [OAuth Provider]
    |                             |                         |                            |
    |--1. POST /auth/{provider}/login-->|                    |                            |
    |                             |--요청 전달-->|                            |
    |                             |                         |--2. OAuth URL 생성-->|      |
    |                             |                         |<--3. OAuth URL 반환--|      |
    |<--4. OAuth URL 반환--------|                         |                            |
    |                             |                         |                            |
    |--5. 사용자 인증 요청------------------------------------------>|      |
    |                             |                         |                            |
    |<--6. 인증 완료, code 반환-------------------------------------|      |
    |                             |                         |                            |
    |--7. GET /oauth2/{provider}/callback?code=xxx-->|                    |                            |
    |                             |--요청 전달-->|                            |
    |                             |                         |--8. code로 토큰 교환-->|      |
    |                             |                         |<--9. Access Token 반환--|      |
    |                             |                         |                            |
    |                             |                         |--10. 사용자 정보 요청-->|      |
    |                             |                         |<--11. 사용자 정보 반환--|      |
    |                             |                         |                            |
    |                             |                         |--12. JWT 토큰 생성--|      |
    |                             |                         |                            |
    |<--13. 리다이렉트 (토큰 포함)-------------------|                         |                            |
```

### 단계별 상세 설명

#### 1단계: 로그인 URL 요청
- **엔드포인트**: `POST /auth/{provider}/login`
- **제공자**: `kakao`, `naver`, `google`
- **요청**: 프론트엔드에서 로그인 버튼 클릭
- **응답**: OAuth 인증 URL 반환
  ```json
  {
    "success": true,
    "message": "로그인 URL 생성 성공",
    "authUrl": "https://kauth.kakao.com/oauth/authorize?client_id=..."
  }
  ```

#### 2단계: 사용자 인증
- 프론트엔드에서 받은 URL로 리다이렉트
- 사용자가 OAuth 제공자 사이트에서 로그인 및 권한 승인

#### 3단계: 콜백 처리
- **엔드포인트**: `GET /oauth2/{provider}/callback?code=xxx`
- OAuth 제공자가 인증 코드(code)와 함께 콜백 호출
- Gateway가 `/oauth2/**` 경로를 Auth Service로 라우팅

#### 4단계: 토큰 교환
- Auth Service가 `code`를 사용해 OAuth 제공자에게 Access Token 요청
- OAuth 제공자가 Access Token 반환

#### 5단계: 사용자 정보 조회
- 받은 Access Token으로 사용자 정보 API 호출
- 사용자 ID, 닉네임, 프로필 이미지 등 수집

#### 6단계: JWT 토큰 생성
- 수집한 사용자 정보를 기반으로 JWT 토큰 생성
- JWT에는 사용자 ID와 닉네임 포함

#### 7단계: 프론트엔드 리다이렉트
- 생성된 JWT 토큰을 쿼리 파라미터로 포함하여 프론트엔드로 리다이렉트
- URL 형식: `http://localhost:3000/dashboard?token={jwt_token}`

---

## API 엔드포인트

### 카카오 OAuth

#### 로그인 URL 생성
- **Method**: `POST`
- **URL**: `http://localhost:8080/auth/kakao/login`
- **Response**: 
  ```json
  {
    "success": true,
    "message": "카카오 로그인 URL 생성 성공",
    "authUrl": "https://kauth.kakao.com/oauth/authorize?..."
  }
  ```

#### 콜백 처리
- **Method**: `GET`
- **URL**: `http://localhost:8080/oauth2/kakao/callback?code=xxx`
- **동작**: 토큰 교환 → 사용자 정보 조회 → JWT 생성 → 프론트엔드 리다이렉트

#### 사용자 정보 조회
- **Method**: `GET`
- **URL**: `http://localhost:8080/auth/kakao/user`
- **Headers**: 
  - `X-User-Id`: 사용자 ID
  - `X-Kakao-Id`: 카카오 ID
  - `X-User-Nickname`: 닉네임
- **Response**:
  ```json
  {
    "success": true,
    "message": "사용자 정보 조회 성공",
    "user": {
      "id": "123",
      "kakaoId": 123456789,
      "nickname": "사용자"
    }
  }
  ```

#### 로그아웃
- **Method**: `GET`
- **URL**: `http://localhost:8080/auth/kakao/logout`

### 네이버 OAuth

#### 로그인 URL 생성
- **Method**: `POST`
- **URL**: `http://localhost:8080/auth/naver/login`
- **Response**: 네이버 인증 URL 반환

#### 콜백 처리
- **Method**: `GET`
- **URL**: `http://localhost:8080/oauth2/naver/callback?code=xxx&state=xxx`
- **특징**: 네이버는 `state` 파라미터를 권장함

#### 사용자 정보 조회
- **Method**: `GET`
- **URL**: `http://localhost:8080/auth/naver/user`
- **Headers**: 
  - `X-User-Id`: 사용자 ID
  - `X-User-Nickname`: 닉네임

### 구글 OAuth

#### 로그인 URL 생성
- **Method**: `POST`
- **URL**: `http://localhost:8080/auth/google/login`
- **특징**: `scope=openid profile email` 포함

#### 콜백 처리
- **Method**: `GET`
- **URL**: `http://localhost:8080/oauth2/google/callback?code=xxx`

#### 사용자 정보 조회
- **Method**: `GET`
- **URL**: `http://localhost:8080/auth/google/user`
- **Headers**: 
  - `X-User-Id`: 사용자 ID
  - `X-User-Nickname`: 닉네임

---

## 주요 컴포넌트

### Controller 계층

#### GoogleController, KakaoController, NaverController
- **역할**: 각 OAuth 제공자별 로그인 URL 생성 및 콜백 처리
- **경로**: `/auth/{provider}/*`
- **주요 메서드**:
  - `{provider}Login()`: 로그인 URL 생성
  - `{provider}Callback()`: 콜백 처리 (토큰 교환, 사용자 정보 조회, JWT 생성)
  - `getUserInfo()`: 사용자 정보 조회
  - `logout()`: 로그아웃

#### OAuth2CallbackController
- **역할**: 통합 콜백 처리 (개발자 콘솔에서 `/oauth2/{provider}/callback`으로 설정된 경우)
- **경로**: `/oauth2/{provider}/callback`
- **특징**: 세 제공자의 콜백을 하나의 컨트롤러에서 처리

### Service 계층

#### GoogleOAuthService, KakaoOAuthService, NaverOAuthService
- **역할**: OAuth 제공자 API와 통신
- **주요 메서드**:
  - `getAccessToken(String code)`: 인증 코드로 Access Token 교환
  - `getUserInfo(String accessToken)`: Access Token으로 사용자 정보 조회
  - `logout(String accessToken)`: 로그아웃 처리

#### JwtService
- **역할**: JWT 토큰 생성 및 검증
- **주요 메서드**:
  - `generateToken(Long userId, String nickname)`: JWT 토큰 생성
  - `parseToken(String token)`: JWT 토큰 파싱
  - `validateToken(String token)`: JWT 토큰 유효성 검증

### DTO 계층

#### TokenResponse (GoogleTokenResponse, KakaoTokenResponse, NaverTokenResponse)
- **역할**: OAuth 제공자로부터 받은 토큰 응답 매핑
- **포함 정보**: accessToken, refreshToken, tokenType, expiresIn 등

#### UserInfo (GoogleUserInfo, KakaoUserInfo, NaverUserInfo)
- **역할**: OAuth 제공자로부터 받은 사용자 정보 매핑
- **포함 정보**: ID, 닉네임, 이름, 프로필 이미지 등

#### Response (ApiResponse, LoginResponse, UserInfoResponse)
- **역할**: API 응답 표준화
- **구조**: success, message, data

---

## 환경 설정

### .env 파일 설정

프로젝트 루트에 `.env` 파일을 생성하고 다음 환경 변수를 설정합니다:

```env
# JWT 설정
JWT_SECRET=your-jwt-secret-key-here
JWT_EXPIRATION=86400000

# 카카오 OAuth2 설정
KAKAO_REST_API_KEY=your-kakao-rest-api-key
KAKAO_CLIENT_SECRET=your-kakao-client-secret
KAKAO_ADMIN_KEY=your-kakao-admin-key
KAKAO_REDIRECT_URI=http://localhost:8080/oauth2/kakao/callback

# 네이버 OAuth2 설정
NAVER_CLIENT_ID=your-naver-client-id
NAVER_CLIENT_SECRET=your-naver-client-secret
NAVER_REDIRECT_URI=http://localhost:8080/oauth2/naver/callback

# 구글 OAuth2 설정
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8080/oauth2/google/callback

# 프론트엔드 설정
FRONTEND_CALLBACK_URL=http://localhost:3000/dashboard
```

### OAuth 제공자 콘솔 설정

#### 카카오 개발자 콘솔
- **Redirect URI**: `http://localhost:8080/oauth2/kakao/callback`
- **사용 API**: 회원이름, 별명, 프로필 사진

#### 네이버 개발자 콘솔
- **서비스 URL**: `http://localhost:8080`
- **Callback URL**: `http://localhost:8080/oauth2/naver/callback`
- **사용 API**: 회원이름, 별명, 프로필 사진

#### 구글 클라우드 콘솔
- **승인된 리디렉션 URI**: `http://localhost:8080/oauth2/google/callback`
- **스코프**: `openid profile email`

---

## 데이터 흐름

### 1. 로그인 요청 흐름

```
Frontend
  ↓ POST /auth/kakao/login
Gateway (8080)
  ↓ 라우팅
Auth Service (8081)
  ↓ KakaoController.kakaoLogin()
  ↓ OAuth URL 생성
  ↓ LoginResponse 반환
Gateway
  ↓ JSON 응답
Frontend
  ↓ window.location.href = authUrl
Kakao 인증 페이지
```

### 2. 콜백 처리 흐름

```
Kakao 인증 완료
  ↓ GET /oauth2/kakao/callback?code=xxx
Gateway (8080)
  ↓ 라우팅
Auth Service (8081)
  ↓ OAuth2CallbackController.kakaoCallback()
  ↓ processKakaoCallback(code)
  ↓ KakaoOAuthService.getAccessToken(code)
  ↓ Kakao API 호출
  ↓ Access Token 수신
  ↓ KakaoOAuthService.getUserInfo(accessToken)
  ↓ Kakao API 호출
  ↓ 사용자 정보 수신
  ↓ JwtService.generateToken(userId, nickname)
  ↓ JWT 토큰 생성
  ↓ 리다이렉트 (토큰 포함)
Frontend (localhost:3000/dashboard?token=xxx)
```

### 3. 사용자 정보 조회 흐름

```
Frontend
  ↓ GET /auth/kakao/user
  ↓ Authorization: Bearer {jwt_token}
Gateway (8080)
  ↓ JWT 검증 (Gateway Filter)
  ↓ 헤더에 사용자 정보 추가
  ↓ X-User-Id, X-Kakao-Id, X-User-Nickname
Auth Service (8081)
  ↓ KakaoController.getUserInfo()
  ↓ 헤더에서 사용자 정보 추출
  ↓ UserInfoResponse 반환
Gateway
  ↓ JSON 응답
Frontend
```

---

## 기술 스택

- **Framework**: Spring Boot
- **Gateway**: Spring Cloud Gateway
- **HTTP Client**: Spring WebClient (Reactive)
- **JWT**: jjwt (io.jsonwebtoken)
- **Build Tool**: Gradle
- **Container**: Docker Compose

---

## 주요 특징

1. **제공자별 독립 패키지**: 각 OAuth 제공자별로 Controller, Service, DTO를 한 폴더에 모아놓아 응집도가 높음
2. **통합 콜백 처리**: OAuth2CallbackController로 모든 제공자의 콜백을 일관되게 처리
3. **JWT 기반 인증**: OAuth 인증 후 JWT 토큰을 발급하여 세션 관리
4. **Gateway 기반 라우팅**: Spring Cloud Gateway를 통한 요청 라우팅 및 CORS 처리
5. **동기 처리**: WebClient를 사용하지만 `.block()`으로 동기 방식으로 처리

---

## 주의사항

1. **보안**: `.env` 파일은 절대 Git에 커밋하지 마세요
2. **Redirect URI**: OAuth 제공자 콘솔에 등록한 Redirect URI와 코드의 URI가 정확히 일치해야 합니다
3. **JWT Secret**: 프로덕션 환경에서는 강력한 랜덤 문자열을 사용하세요
4. **에러 처리**: OAuth 제공자로부터 에러가 반환될 경우 프론트엔드로 에러와 함께 리다이렉트됩니다

---

## 트러블슈팅

### redirect_uri_mismatch 에러
- **원인**: OAuth 제공자 콘솔에 등록한 Redirect URI와 요청 URI가 일치하지 않음
- **해결**: 콘솔의 Redirect URI 설정을 확인하고 정확히 일치시킴

### missing_code 에러
- **원인**: 콜백에 `code` 파라미터가 없음
- **해결**: OAuth 제공자 콘솔의 Redirect URI 설정 확인

### JWT 토큰 검증 실패
- **원인**: Gateway와 Auth Service의 JWT Secret이 일치하지 않음
- **해결**: `.env` 파일의 `JWT_SECRET`이 동일한지 확인

