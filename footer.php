<script>
(function(){
  var rootElement = document.documentElement;

  function getStoredTheme() {
    try {
      return localStorage.getItem('theme');
    } catch (e) {
      return null;
    }
  }

  function setStoredTheme(theme) {
    try {
      localStorage.setItem('theme', theme);
    } catch (e) {}
  }

  function getCurrentTheme() {
    return rootElement && rootElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function updateIcons(theme) {
    var sunIcon = document.querySelector('.hdr-sun-icon');
    var moonIcon = document.querySelector('.hdr-moon-icon');

    if (!sunIcon || !moonIcon) return;

    if (theme === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }

  updateIcons(getStoredTheme() || getCurrentTheme());

  var themeToggle = document.getElementById('themeToggle');
  if (themeToggle && rootElement) {
    themeToggle.addEventListener('click', function() {
      var currentTheme = getCurrentTheme();

      if (currentTheme === 'dark') {
        rootElement.removeAttribute('data-theme');
        setStoredTheme('light');
        updateIcons('light');
      } else {
        rootElement.setAttribute('data-theme', 'dark');
        setStoredTheme('dark');
        updateIcons('dark');
      }
    });
  }

  function closeDrawer(){
    var burger = document.getElementById('hdrBurger');
    var drawer = document.getElementById('hdrDrawer');

    if (burger) {
      burger.classList.remove('is-open');
      burger.setAttribute('aria-expanded', 'false');
    }

    if (drawer) {
      drawer.classList.remove('is-open');
      drawer.setAttribute('aria-hidden', 'true');
    }
  }

  function sslProToggleMenu(){
    var burger = document.getElementById('hdrBurger');
    var drawer = document.getElementById('hdrDrawer');
    if (!burger || !drawer) return;

    var isOpen = burger.classList.toggle('is-open');
    drawer.classList.toggle('is-open', isOpen);
    burger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    drawer.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
  }
  window.sslProToggleMenu = sslProToggleMenu;

  document.addEventListener('click', function(e){
    var hdr = document.getElementById('siteHeader');
    if (hdr && !hdr.contains(e.target)) {
      closeDrawer();
    }
  });

  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape') {
      closeDrawer();
    }
  });
})();
</script>

</body>
</html>
