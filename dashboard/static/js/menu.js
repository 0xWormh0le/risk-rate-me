
$(function () {
    "use strict";
    $(function () {
        $(".preloader").fadeOut();
    });

    // ==============================================================
    // This is for the top header part and sidebar part
    // ==============================================================
    var set = function () {
            var width = (window.innerWidth > 0) ? window.innerWidth : this.screen.width;
            var topOffset = 70;
            if (width < 1170) {
                $("body").addClass("mini-sidebar");
                $(".navbar-brand span").hide();

            }
            else {
                $("body").removeClass("mini-sidebar");
                $(".navbar-brand span").show();

            }

            var height = ((window.innerHeight > 0) ? window.innerHeight : this.screen.height) - 1;
            height = height - topOffset;
            if (height < 1) {
                height = 1;
            }
            if (height > topOffset) {
                $(".page-wrapper").css("min-height", (height) + "px");
            }

    };
    $(window).ready(set);
    $(window).on("resize", set);

    $(".sidebartoggler").on("click", function () {
        if ($("body").hasClass("mini-sidebar")) {
            $("body").trigger("resize");
            $(".scroll-sidebar, .slimScrollDiv").css("overflow", "hidden").parent().css("overflow", "visible");
            $("body").removeClass("mini-sidebar");
            $(".navbar-brand span").show();

        }
        else {
            $("body").trigger("resize");
            $(".scroll-sidebar, .slimScrollDiv").css("overflow-x", "visible").parent().css("overflow", "visible");
            $("body").addClass("mini-sidebar");
            $(".navbar-brand span").hide();

        }
    });
    // topbar stickey on scroll

    $(".fix-header .topbar").stick_in_parent({

    });

    $(".floating-labels .form-control").on("focus blur", function (e) {
        $(this).parents(".form-group").toggleClass("focused", (e.type === "focus" || this.value.length > 0));
    }).trigger("blur");

    // this is for close icon when navigation open in mobile view
    $(".nav-toggler").click(function () {
        $("body").toggleClass("show-sidebar");
        $(".nav-toggler i").toggleClass("mdi mdi-menu");
        $(".nav-toggler i").addClass("mdi mdi-close");
    });

    $(".search-box a, .search-box .app-search .srh-btn").on("click", function () {
        $(".app-search").toggle(200);
    });


    // ==============================================================
    // Auto select left navbar
    // ==============================================================
    $(function () {
        var url = window.location;
        var element = $("ul#sidebarnav a").filter(function () {
            return this.href == url;
        }).addClass("active").parent().addClass("active");
        while (true) {
            if (element.is("li")) {
                element = element.parent().addClass("in").parent().addClass("active");
            }
            else {
                break;
            }
        }

    });
    // ==============================================================
    //tooltip
    // ==============================================================
    $(function () {
            $("[data-toggle='tooltip']").tooltip();
        })
        // ==============================================================
        //Popover
        // ==============================================================
    $(function () {
            $("[data-toggle='popover']").popover();
        })
        // ==============================================================
        // Sidebarmenu
        // ==============================================================
    $(function () {
        $("#sidebarnav").metisMenu();
    });
    // ==============================================================
    // Slimscrollbars
    // ==============================================================



  $(".scroll-sidebar").slimScroll({
    position: "left",
    size: "5px",
    height: "100%",
    color: "#dcdcdc",
    allowPageScroll: true,
  });




    // ==============================================================
    // Resize all elements
    // ==============================================================
    $("body").trigger("resize");

    });


  $("a[data-action='collapse']").on("click", function (i) {
    i.preventDefault(),
    $(this).closest(".card").find("[data-action='collapse'] i").toggleClass("ti-minus ti-plus"),
    $(this).closest(".card").children(".card-body").collapse("toggle")
  }),
  $("a[data-action='expand']").on("click", function (i) {
    i.preventDefault(),
    $(this).closest(".card").find("[data-action='expand'] i").toggleClass("mdi-arrow-expand mdi-arrow-compress"),
    $(this).closest(".card").toggleClass("card-fullscreen")
  });
