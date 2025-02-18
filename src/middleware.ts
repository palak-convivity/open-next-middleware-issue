import { cookies } from "next/headers";
import {NextResponse } from "next/server";
// import { jwtDecode } from "jwt-decode"; // Only decodes, does NOT verify signature
import JWT from "@tsndr/cloudflare-worker-jwt";
// const protectedRoutes = ["/admin", "/parent", "/student", "/teacher"];
// const publicRoutes = [
//   "/login",
//   "/create-account",
//   "/",
//   "/forget-password",
//   "/verify",
//   "/reset-password",
// ];

export default async function middleware() {
  //   const path = req.nextUrl.pathname;
  //   const isProtectedRoute = protectedRoutes.includes("/" + path.split("/")[1]);
  //   const isPublicRoute = publicRoutes.includes("/" + path.split("/")[1]);
  const secret = process.env.NEXT_PAYLOAD_SECRET || "00dd12fc777c6bd07c47b003";
  // 1️⃣ Get token from cookies
  const token = cookies().get("payload-token")?.value || "";

  // 2️⃣ Decode token (No verification, avoids Edge runtime crypto issues)
  //   let session: DecodedToken | null = null;
  //   if (token && secret) {
  //     try {
  //       // const isValid = await jwt.verify(
  //       //   token,
  //       //   await generateSecret(secret || ""),
  //       //   "HS256"
  //       // );
  //       // if (!isValid) {
  //       //    console.log({
  //       //     valid: false,
  //       //     decoded: null,
  //       //     message: "Token is invalid",
  //       //   });
  //       // }
  //       // session = jwtDecode<DecodedToken>(token);
  //       // console.log(session,secret, "isValidisValid", token);
  //     } catch (error) {
  //       console.error("Failed to decode token:", error);
  //     }
  //   }
  // testTokenVerification();

  const {
    valid,
    decoded: decodedSession,
    message,
  } = await validateAndDecodeToken(token, secret);
  //   // 3️⃣ Redirect to login if token is missing and route is protected

  console.log(valid, "valid", message, decodedSession);

  //   if (isProtectedRoute && !decodedSession?.id) {
  //     return NextResponse.redirect(new URL("/login", req.nextUrl));
  //   }

  //   // 4️⃣ Redirect to dashboard if logged in user accesses public routes
  //   if (decodedSession?.id && isPublicRoute) {
  //     const url =
  //       decodedSession.role === "secondary-parent"
  //         ? "/parent"
  //         : `/${decodedSession.role}`;
  //     return NextResponse.redirect(new URL(url, req.nextUrl));
  //   }

  return NextResponse.next();
}

// Middleware should not run on static files
export const config = {
  matcher: ["/((?!api|_next/static|_next/image|.*\\.png$).*)"],
};

// interface DecodedToken {
//   id: string;
//   email: string;
//   role: string;
//   firstName: string;
//   lastName: string;
// }

// export async function validateAndDecodeToken(token: string): Promise<{
//   valid: boolean;
//   decoded?: DecodedToken | null;
//   message?: string;
// }> {
//   try {
//     const isValid = await jwt.verify(
//       token,
//       '00dd12fc777c6bd07c47b003',
//     //   await generateSecret(process.env.NEXT_PAYLOAD_SECRET || "00dd12fc777c6bd07c47b003"),
//     { algorithm: "HS256" }
//     );
// console.log(isValid, 'isValidisValid');

//     if (!isValid) {
//       return {
//         valid: false,
//         decoded: null,
//         message: "Token is invalid",
//       };
//     }

//     const { payload } = jwt.decode(token);
// console.log(payload, 'payloadpayloadpayload');

//     return {
//       valid: true,
//       decoded: payload as DecodedToken,
//     };
//   } catch (error) {
//     // Handle error
//     console.log(error);

//     return {
//       valid: false,
//       message:
//         error instanceof Error ? error.message : "Token validation failed",
//     };
//   }
// }
// async function generateSecret(secret: string) {
//   const encoder = new TextEncoder();
//   const data = encoder.encode(secret);
//   const hashBuffer = await crypto.subtle.digest("SHA-256", data);
//   const hashArray = Array.from(new Uint8Array(hashBuffer));
//   const hashHex = hashArray
//     .map((b) => b.toString(16).padStart(2, "0"))
//     .join("");
//   return hashHex.slice(0, 32);
// }

// export async function validateAndDecodeToken(token: string): Promise<{
//     valid: boolean;
//     decoded?: unknown;
//     message?: string;
// }> {
//     const SECRET = new TextEncoder().encode("00dd12fc777c6bd07c47b003");
//   try {
//     const isValid = await JWT.verify(token,SECRET, {algorithm:'HS256'});
//     // console.log(JSON.stringify(await JWT.verify(token, SECRET)), "isValid", await generateSecret(SECRET), SECRET);

//     if (!isValid) {
//       return {
//         valid: false,
//         decoded: null,
//         message: "Token is invalid",
//       };
//     }

//     const decoded = await JWT.decode(token);
//     console.log(decoded, "decoded");

//     if (!decoded || !decoded.payload) {
//       return {
//         valid: false,
//         decoded: null,
//         message: "Decoded token is empty",
//       };
//     }

//     // Check expiration
//     const { exp } = decoded.payload;
//     const currentTime = Math.floor(Date.now() / 1000); // Convert to seconds

//     if (exp && exp < currentTime) {
//       return {
//         valid: false,
//         decoded: null,
//         message: "Token has expired time",
//       };
//     }

//     return {
//       valid: true,
//       decoded: decoded?.payload,
//     };
//   } catch (error) {
//     console.log(error);

//     return {
//       valid: false,
//       message:
//         error instanceof Error ? error.message : "Token validation failed",
//     };
//   }
// }

// //
// // const SECRET = "00dd12fc777c6bd07c47b003";
// // const TOKEN =
// //   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjgxNzZjOTAwLWM2OWYtNDI2ZS04NzBmLTA1NjJjOTJhNzg3YSIsImNvbGxlY3Rpb24iOiJ1c2VycyIsImVtYWlsIjoiYWxrYUBtZnQuY29tIiwiZmlyc3ROYW1lIjoiQWxrYSIsImxhc3ROYW1lIjoiU2hhcm1hIiwicm9sZSI6InN0dWRlbnQiLCJpYXQiOjE3Mzk3NzEyMTYsImV4cCI6MTc0MjM2MzIxNn0._imz7fqy4Z9DykVVJF4YgUI5jc0VuFDrjiXQrQvz6b0";

// // async function testTokenVerification() {
// //   try {
// //     console.log("Testing token verification...");

// //     // Verify the token
// //     const isValid = await JWT.verify(TOKEN, "00dd12fc777c6bd07c47b003");
// //     console.log("Verification Result:", isValid);

// //     // Decode the token
// //     const decoded = await JWT.decode(TOKEN);
// //     console.log("Decoded Token:", decoded);
// //   } catch (error) {
// //     console.error("Error during verification:", error);
// //   }
// // }

// import { JWT } from "@tsndr/cloudflare-worker-jwt";

// const SECRET_STRING = "00dd12fc777c6bd07c47b003";

// async function getSecretKey(): Promise<CryptoKey> {
//   const encoder = new TextEncoder();
//   const keyData = encoder.encode(SECRET_STRING);
//   return await crypto.subtle.importKey(
//     "raw",
//     keyData,
//     { name: "HMAC", hash: "SHA-256" },
//     false,
//     ["verify"]
//   );
// }

async function generateSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

export async function validateAndDecodeToken(
  token: string,
  secret: string
): Promise<{
  valid: boolean;
  decoded?: unknown;
  message?: string;
}> {
  try {
    console.log("Received token:", token);
    const SECRET_STRING = await generateSecret(secret);

    console.log("Using secret:", SECRET_STRING, ' ', secret);

    // Verify the token using the hashed secret
      const isValid = await JWT.verify(token, SECRET_STRING, "HS256");
      console.log("Verification result:", isValid ? "Valid ✅" : "Invalid ❌", isValid, SECRET_STRING);

    //   if (!isValid) {
    //     return {
    //       valid: false,
    //       decoded: null,
    //       message: "Token is invalid or signature mismatch",
    //     };
    //   }

    // Decode the token
    // const decoded = await verifyJwt(token, secret);
    //   const decoded = await JWT.decode(token);
    // console.log("Decoded token:", decoded);

    // Check expiration
    // const { exp, iat } = decoded.payload;
    // const currentTime = Math.floor(Date.now() / 1000);
    // console.log(
    //   "Current time:",
    //   currentTime,
    //   "Token iat:",
    //   iat,
    //   "Token exp:",
    //   exp
    // );

    // if (exp && exp < currentTime) {
    //   return {
    //     valid: false,
    //     decoded: null,
    //     message: "Token has expired",
    //   };
    // }

    return {
      valid: true,
      // decoded: decoded.payload,
    };
  } catch (error) {
    //   console.error("JWT verification error:", JSON.stringify(error));

    return {
      valid: false,
      message:
        error instanceof Error ? error.message : "Token validation failed",
    };
  }
}

// async function verifyJwt(token: string, secret: string | undefined) {
//   const [header, payload, signature] = token.split(".");

//   // Decode Base64 URL encoding
//   const decodeBase64Url = (base64Url: string) => {
//     const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
//     const padding = "=".repeat((4 - (base64.length % 4)) % 4);
//     return new TextDecoder().decode(
//       Uint8Array.from(atob(base64 + padding), (c) => c.charCodeAt(0))
//     );
//   };

//   const decodedHeader = JSON.parse(decodeBase64Url(header));
//   const decodedPayload = decodeBase64Url(payload);

//   // Perform the actual verification using Web Crypto API
//   const data = new TextEncoder().encode(header + "." + payload); // Data to verify
//   const key = await crypto.subtle.importKey(
//     "raw",
//     new TextEncoder().encode(secret),
//     { name: "HMAC", hash: { name: "SHA-256" } },
//     false,
//     ["verify"]
//   );

//   const isValid = await crypto.subtle.verify(
//     "HMAC",
//     key,
//     new Uint8Array(
//       atob(signature)
//         .split("")
//         .map((c) => c.charCodeAt(0))
//     ),
//     data
//   );

//   return { isValid, payload: JSON.parse(decodedPayload), decodedHeader };
//   // if (isValid) {
//   //   return JSON.parse(decodedPayload); // return decoded payload if valid
//   // } else {
//   //   return null;
//   // }
// }
