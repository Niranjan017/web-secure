document.addEventListener('DOMContentLoaded', function () {
  const container = document.querySelector('.auth-container');
  const signinBtn = document.getElementById('show-signin');
  const signupBtn = document.getElementById('show-signup');
  const signinForm = document.getElementById('signin-form');
  const signupForm = document.getElementById('signup-form');
  const heroTitle = document.getElementById('hero-title');
  const heroText = document.getElementById('hero-text');

  if (container && signinBtn && signupBtn && signinForm && signupForm && heroTitle && heroText) {
    // Switch to Sign In form
    signinBtn.addEventListener('click', () => {
      container.classList.remove('move-left');
      container.classList.add('move-right');
      signinForm.classList.add('active');
      signupForm.classList.remove('active');
      signinBtn.classList.add('active');
      signupBtn.classList.remove('active');
      heroTitle.textContent = "Welcome Back!";
      heroText.textContent = "Sign in to monitor, detect, and secure your digital assets with Web Secura.";
    });

    // Switch to Sign Up form
    signupBtn.addEventListener('click', () => {
      container.classList.remove('move-right');
      container.classList.add('move-left');
      signupForm.classList.add('active');
      signinForm.classList.remove('active');
      signupBtn.classList.add('active');
      signinBtn.classList.remove('active');
      heroTitle.textContent = "Join Web Secura Today!";
      heroText.textContent = "Create your account to start protecting your applications and data.";
    });

    const switchToSignin = document.getElementById('switch-to-signin');
    if (switchToSignin) {
      switchToSignin.addEventListener('click', function (e) {
        e.preventDefault();
        signinBtn.click();
      });
    }

    // Handle Sign Up
    signupForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const name = document.getElementById('signup-name').value.trim();
      const email = document.getElementById('signup-email').value.trim();
      const password = document.getElementById('signup-password').value;

      try {
        const response = await fetch('http://localhost:3000/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password })
        });

        const data = await response.json();
        if (response.ok) {
          alert('Signup successful! Please sign in.');
          signinBtn.click();
          signupForm.reset();
        } else {
          alert(data.error || 'Signup failed.');
        }
      } catch (err) {
        console.error(err);
        alert('Something went wrong during signup.');
      }
    });

    // Handle Sign In
    signinForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const email = document.getElementById('signin-email').value.trim();
      const password = document.getElementById('signin-password').value;

      try {
        const response = await fetch('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (response.ok && data.token) {
          // Save token in localStorage
          localStorage.setItem('token', data.token);

          alert('Login successful!');
          signinForm.reset();

          // Redirect to dashboard page (change if your dashboard URL differs)
          window.location.href = 'dash.html';
        } else {
          alert(data.error || 'Login failed.');
        }
      } catch (err) {
        console.error(err);
        alert('Something went wrong during login.');
      }
    });
  }
});
