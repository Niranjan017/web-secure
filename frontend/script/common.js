// common.js

//mobile menu toggle
document.addEventListener('DOMContentLoaded', function () {
  const hamburger = document.getElementById('toggle');
  const navLinks = document.querySelector('.nav-links');

  if (hamburger && navLinks) {
    hamburger.addEventListener('click', function () {
      this.classList.toggle('on');
      navLinks.classList.toggle('show');
    });
  }

  const statItems = document.querySelectorAll('.stat-item');
  const testimonialCards = document.querySelectorAll('.testimonial-card');

  function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return rect.top < window.innerHeight && rect.bottom >= 0;
  }

  function checkScroll() {
    statItems.forEach(item => isInViewport(item) && item.classList.add('active'));
    testimonialCards.forEach(card => isInViewport(card) && card.classList.add('active'));
  }

  window.addEventListener('scroll', checkScroll);
  window.addEventListener('load', checkScroll);
});



//logout js
const token = sessionStorage.getItem('token');
const loginLogoutLink = document.getElementById('login-logout-link');

if (token) {
  // User is logged in → show Logout
  loginLogoutLink.textContent = 'Logout';
  loginLogoutLink.href = '#';
  loginLogoutLink.addEventListener('click', function (e) {
    e.preventDefault();
    sessionStorage.removeItem('token'); // Clear token on logout
    window.location.href = 'index.html'; // Redirect to login page
  });
} else {
  // User is not logged in → show Login
  loginLogoutLink.textContent = 'Login';
  loginLogoutLink.href = 'login.html';
}