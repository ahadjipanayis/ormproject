// static/js/admin.js
(function($) {
    $(document).ready(function() {
        // Apply Select2 to the portfolio filter dropdown
        $("select[name='portfolios']").select2({
            placeholder: "Select portfolios",
            allowClear: true,
            width: '100%'  // Adjust width as needed
        });
    });
})(django.jQuery);