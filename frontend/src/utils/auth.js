// src/utils/auth.js

export function requireAuth() {
    // Verificamos si estamos en el navegador
    if (typeof window !== 'undefined') {
        // Verificamos si la clave 'authenticated' está en sessionStorage
        const isAuthenticated = sessionStorage.getItem('authenticated');


        // Si no está autenticado, redirigimos al login
        if (!isAuthenticated) {
            window.location.href = '/login';
        }
    }
}
