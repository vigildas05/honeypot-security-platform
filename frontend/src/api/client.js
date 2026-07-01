const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export async function login(username, password) {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!response.ok) {
    throw new Error("Login failed");
  }

  return response.json();
}

export async function apiGet(path) {
  const token = localStorage.getItem("dashboardToken");
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      authorization: `Bearer ${token}`
    }
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${path}`);
  }

  return response.json();
}
