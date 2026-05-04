<script>
(function(){
  // --- Theme Toggle Logic ---
  const themeToggle = document.getElementById('themeToggle');
  const sunIcon = document.querySelector('.hdr-sun-icon');
  const moonIcon = document.querySelector('.hdr-moon-icon');
  const rootElement = document.documentElement;

  // Icon sync function based on current state
  function updateIcons(theme) {
    if (theme === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }

  // Initial Sync
  updateIcons(localStorage.getItem('theme'));

  // Toggle Action
  themeToggle.addEventListener('click', function() {
    const currentTheme = rootElement.getAttribute('data-theme');
    if (currentTheme === 'dark') {
      rootElement.removeAttribute('data-theme');
      localStorage.setItem('theme', 'light');
      updateIcons('light');
    } else {
      rootElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('theme', 'dark');
      updateIcons('dark');
    }
  });

  // --- Mobile Menu Logic ---
  function sslProToggleMenu(){
    var burger = document.getElementById('hdrBurger');
    var drawer = document.getElementById('hdrDrawer');
    if(!burger||!drawer) return;
    var isOpen = burger.classList.toggle('is-open');
    drawer.classList.toggle('is-open', isOpen);
    burger.setAttribute('aria-expanded', isOpen);
    drawer.setAttribute('aria-hidden', !isOpen);
  }
  window.sslProToggleMenu = sslProToggleMenu;

  // Close drawer on outside click
  document.addEventListener('click', function(e){
    var hdr = document.getElementById('siteHeader');
    if(hdr && !hdr.contains(e.target)){
      var burger = document.getElementById('hdrBurger');
      var drawer = document.getElementById('hdrDrawer');
      if(burger){ burger.classList.remove('is-open'); burger.setAttribute('aria-expanded','false'); }
      if(drawer){ drawer.classList.remove('is-open'); drawer.setAttribute('aria-hidden','true'); }
    }
  });
})();
</script>

</body>
</html>
