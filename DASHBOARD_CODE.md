# Dashboard 페이지 코드

## Next.js Dashboard 페이지 (app/dashboard/page.tsx)

```tsx
'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function DashboardPage() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [isLoggingOut, setIsLoggingOut] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [userInfo, setUserInfo] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);

    // 토큰 처리 및 사용자 정보 조회
    useEffect(() => {
        const initialize = async () => {
            try {
                // 1. URL에서 토큰 확인 (카카오 로그인 후 리다이렉트된 경우)
                const tokenFromUrl = searchParams.get('token');
                
                if (tokenFromUrl) {
                    // 토큰을 localStorage에 저장
                    localStorage.setItem('access_token', tokenFromUrl);
                    
                    // URL에서 토큰 파라미터 제거 (보안을 위해)
                    router.replace('/dashboard', { scroll: false });
                }

                // 2. localStorage에서 토큰 가져오기
                const token = localStorage.getItem('access_token');
                
                if (!token) {
                    // 토큰이 없으면 로그인 페이지로 이동
                    setError('인증이 필요합니다.');
                    router.push('/');
                    return;
                }

                // 3. 백엔드 API로 현재 사용자 정보 조회
                const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';

                const response = await fetch(`${gatewayUrl}/api/auth/me`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Authorization': `Bearer ${token}`, // JWT 토큰을 Authorization 헤더에 포함
                        'Content-Type': 'application/json',
                    },
                });

                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.success && data.user) {
                        setUserInfo(data.user); // user 객체만 저장
                        setError(null);
                    } else {
                        setError(data.message || '사용자 정보를 가져올 수 없습니다.');
                    }
                } else if (response.status === 401) {
                    // 토큰이 유효하지 않으면 로그인 페이지로 이동
                    localStorage.removeItem('access_token');
                    setError('인증이 필요합니다.');
                    router.push('/');
                } else {
                    const errorData = await response.json().catch(() => ({ message: '사용자 정보를 가져올 수 없습니다.' }));
                    setError(errorData.message || '사용자 정보를 가져올 수 없습니다.');
                }
            } catch (err) {
                console.error('사용자 정보 조회 실패:', err);
                setError('서버 연결에 실패했습니다.');
            } finally {
                setIsLoading(false);
            }
        };

        initialize();
    }, [router, searchParams]);

    const handleLogout = async () => {
        setIsLoggingOut(true);

        try {
            const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';

            // 백엔드 API로 로그아웃 요청
            await fetch(`${gatewayUrl}/api/auth/logout`, {
                method: 'POST',
                credentials: 'include',
            });

            // 로컬 스토리지에서 토큰 제거
            localStorage.removeItem('access_token');

            // 로그인 페이지로 이동
            router.push('/');
        } catch (err) {
            console.error('로그아웃 실패:', err);
            // 에러가 발생해도 토큰 제거하고 로그인 페이지로 이동
            localStorage.removeItem('access_token');
            router.push('/');
        } finally {
            setIsLoggingOut(false);
        }
    };

    // 로딩 중
    if (isLoading) {
        return (
            <div className="relative flex min-h-screen overflow-hidden bg-gradient-to-br from-purple-400 via-pink-400 to-orange-400">
                <div className="absolute inset-0 overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-purple-500/60 via-pink-500/60 to-orange-500/60"></div>
                </div>
                <div className="flex flex-1 items-center justify-center p-6 lg:p-12 relative z-10">
                    <div className="text-center">
                        <div className="w-16 h-16 border-4 border-white border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                        <p className="text-white text-lg font-semibold">로딩 중...</p>
                    </div>
                </div>
            </div>
        );
    }

    // 에러 발생
    if (error && !userInfo) {
        return (
            <div className="relative flex min-h-screen overflow-hidden bg-gradient-to-br from-purple-400 via-pink-400 to-orange-400">
                <div className="absolute inset-0 overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-purple-500/60 via-pink-500/60 to-orange-500/60"></div>
                </div>
                <div className="flex flex-1 items-center justify-center p-6 lg:p-12 relative z-10">
                    <div className="text-center text-white">
                        <p className="text-xl font-semibold mb-4">{error}</p>
                        <button
                            onClick={() => router.push('/')}
                            className="px-6 py-3 bg-white text-purple-600 rounded-xl font-semibold hover:bg-gray-100 transition-colors"
                        >
                            로그인 페이지로 이동
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="relative flex min-h-screen overflow-hidden bg-gradient-to-br from-purple-400 via-pink-400 to-orange-400">
            {/* 인스타그램 스타일 배경 */}
            <div className="absolute inset-0 overflow-hidden">
                {/* 메인 그라데이션 배경 */}
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/60 via-pink-500/60 to-orange-500/60"></div>
                {/* 애니메이션 그라데이션 원들 */}
                <div className="absolute -top-40 -right-40 h-[700px] w-[700px] rounded-full bg-gradient-to-br from-purple-400/50 via-pink-400/40 to-transparent blur-3xl animate-pulse-glow"></div>
                <div className="absolute -bottom-40 -left-40 h-[700px] w-[700px] rounded-full bg-gradient-to-tr from-orange-400/50 via-yellow-400/40 to-transparent blur-3xl animate-pulse-glow" style={{ animationDelay: '1.5s' }}></div>
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[600px] w-[600px] rounded-full bg-gradient-to-r from-pink-400/40 via-purple-400/40 to-rose-400/40 blur-3xl animate-pulse-glow" style={{ animationDelay: '3s' }}></div>
                <div className="absolute top-20 left-1/4 h-[500px] w-[500px] rounded-full bg-gradient-to-br from-rose-400/45 to-pink-400/35 blur-3xl animate-pulse-glow" style={{ animationDelay: '0.5s' }}></div>
                <div className="absolute bottom-20 right-1/4 h-[550px] w-[550px] rounded-full bg-gradient-to-tl from-orange-400/45 to-amber-400/35 blur-3xl animate-pulse-glow" style={{ animationDelay: '2.5s' }}></div>
                {/* 빛나는 효과 */}
                <div className="absolute top-0 left-0 right-0 h-1/3 bg-gradient-to-b from-white/20 via-white/10 to-transparent"></div>
                <div className="absolute bottom-0 left-0 right-0 h-1/3 bg-gradient-to-t from-white/10 to-transparent"></div>
            </div>

            {/* 메인 컨텐츠 */}
            <div className="flex flex-1 items-center justify-center p-6 lg:p-12 relative z-10">
                <div className="w-full max-w-2xl text-center animate-zoom-in">
                    {/* 성공 메시지 카드 */}
                    <div className="relative">
                        {/* 카드 배경 */}
                        <div className="absolute inset-0 rounded-3xl bg-gradient-to-br from-white to-gray-50 shadow-2xl dark:from-gray-900 dark:to-gray-800"></div>
                        <div className="absolute inset-0 rounded-3xl bg-white/90 backdrop-blur-xl border border-gray-200/50 dark:bg-gray-900/90 dark:border-gray-700/50"></div>

                        {/* 카드 내용 */}
                        <div className="relative px-8 py-16 lg:px-12 lg:py-20">
                            {/* 성공 아이콘 */}
                            <div className="flex justify-center mb-8">
                                <div className="relative">
                                    {/* 배경 원 */}
                                    <div className="absolute inset-0 rounded-full bg-gradient-to-br from-green-400 to-emerald-500 blur-xl opacity-50 animate-pulse-glow"></div>
                                    {/* 아이콘 컨테이너 */}
                                    <div className="relative w-24 h-24 lg:w-32 lg:h-32 rounded-full bg-gradient-to-br from-green-400 to-emerald-500 flex items-center justify-center shadow-2xl transform transition-all duration-300 hover:scale-110">
                                        <svg
                                            className="w-12 h-12 lg:w-16 lg:h-16 text-white"
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={3}
                                                d="M5 13l4 4L19 7"
                                            />
                                        </svg>
                                    </div>
                                </div>
                            </div>

                            {/* 성공 메시지 */}
                            <h1 className="text-4xl lg:text-6xl font-bold text-gray-900 dark:text-white mb-4 transform transition-all duration-500 hover:scale-105">
                                카카오 로그인이
                                <br />
                                <span className="bg-gradient-to-r from-yellow-400 via-yellow-500 to-yellow-600 bg-clip-text text-transparent">
                                    성공했습니다!
                                </span>
                            </h1>

                            {/* 사용자 정보 표시 (백엔드에서 받아온 경우) */}
                            {userInfo && (
                                <div className="mb-6">
                                    {userInfo.nickname && (
                                        <p className="text-xl lg:text-2xl text-gray-700 dark:text-gray-200 font-semibold mb-2">
                                            안녕하세요, <span className="text-purple-600 dark:text-purple-400">{userInfo.nickname}</span>님!
                                        </p>
                                    )}
                                    {userInfo.email && (
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            {userInfo.email}
                                        </p>
                                    )}
                                </div>
                            )}

                            <p className="text-lg lg:text-xl text-gray-600 dark:text-gray-300 mb-12 mt-6">
                                환영합니다! 서비스를 이용하실 수 있습니다.
                            </p>

                            {/* 로그아웃 버튼 */}
                            <div className="flex justify-center">
                                <button
                                    onClick={handleLogout}
                                    disabled={isLoggingOut}
                                    className="group relative px-8 py-4 lg:px-12 lg:py-5 rounded-xl bg-gradient-to-r from-gray-700 to-gray-800 hover:from-gray-600 hover:to-gray-700 text-white font-semibold text-lg lg:text-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105 active:scale-95 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:scale-100"
                                >
                                    {isLoggingOut ? (
                                        <span className="flex items-center justify-center gap-3">
                                            <svg
                                                className="w-6 h-6 animate-spin"
                                                fill="none"
                                                viewBox="0 0 24 24"
                                            >
                                                <circle
                                                    className="opacity-25"
                                                    cx="12"
                                                    cy="12"
                                                    r="10"
                                                    stroke="currentColor"
                                                    strokeWidth="4"
                                                />
                                                <path
                                                    className="opacity-75"
                                                    fill="currentColor"
                                                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                                                />
                                            </svg>
                                            로그아웃 중...
                                        </span>
                                    ) : (
                                        <span className="flex items-center justify-center gap-3">
                                            <svg
                                                className="w-6 h-6 transition-transform group-hover:-translate-x-1"
                                                fill="none"
                                                stroke="currentColor"
                                                viewBox="0 0 24 24"
                                            >
                                                <path
                                                    strokeLinecap="round"
                                                    strokeLinejoin="round"
                                                    strokeWidth={2}
                                                    d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                                                />
                                            </svg>
                                            로그아웃
                                        </span>
                                    )}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
```

## Next.js 15 App Router 주의사항

`useSearchParams`를 사용할 때는 `Suspense`로 감싸야 할 수 있습니다:

```tsx
import { Suspense } from 'react';

function DashboardContent() {
    // 위의 DashboardPage 코드
}

export default function DashboardPage() {
    return (
        <Suspense fallback={<div>Loading...</div>}>
            <DashboardContent />
        </Suspense>
    );
}
```

## 주요 기능

1. **토큰 처리**: URL에서 토큰을 받아 localStorage에 저장
2. **사용자 정보 조회**: `/api/auth/me` 엔드포인트로 사용자 정보 가져오기
3. **에러 처리**: 토큰이 없거나 유효하지 않으면 로그인 페이지로 리다이렉트
4. **로딩 상태**: 로딩 중 UI 표시
5. **로그아웃**: 토큰 제거 후 로그인 페이지로 이동

