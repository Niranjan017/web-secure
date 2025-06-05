const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';

    const loginLogoutLink = document.getElementById('login-logout-link');

    if (isLoggedIn) {
        // User is logged in, show Logout
        loginLogoutLink.textContent = 'Logout';
        loginLogoutLink.href = '#';
        loginLogoutLink.addEventListener('click', function (e) {
            e.preventDefault();
            localStorage.setItem('isLoggedIn', 'false');
            window.location.href = 'login.html';
        });
    } else {
        // User is not logged in, show Login
        loginLogoutLink.textContent = 'Login';
        loginLogoutLink.href = 'login.html';
    }