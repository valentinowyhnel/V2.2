// Shared UI helpers
// Initialize Bootstrap tooltips and popovers for the whole site
(function(){
  if (typeof window.jQuery === 'undefined') return;
  (function($){
    $(function(){
      try {
        // initialize tooltips by selector so elements added later will work
        $('body').tooltip({ selector: '[data-toggle="tooltip"]' });
      } catch(e){ console.warn('tooltip init failed', e); }
      try {
        // optional: initialize popovers if used
        $('body').popover({ selector: '[data-toggle="popover"]', trigger: 'focus' });
      } catch(e){ /* no popovers used */ }
    });
  })(window.jQuery);
})();
