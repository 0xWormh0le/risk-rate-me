var revapi41,
    tpj;
(function() {
    if (!/loaded|interactive|complete/.test(document.readyState)) document.addEventListener("DOMContentLoaded", onLoad);
    else onLoad();

    function onLoad() {
        if (tpj === undefined) {
            tpj = jQuery;
            if ("off" == "on") tpj.noConflict();
        }
        if (tpj("#rev_slider_41_1").revolution == undefined) {
            revslider_showDoubleJqueryError("#rev_slider_41_1");
        } else {
            revapi41 = tpj("#rev_slider_41_1").show().revolution({
                sliderType: "standard",
                jsFileLocation: "static/plugins/revolution/js/",
                sliderLayout: "auto",
                dottedOverlay: "none",
                delay: 9000,
                navigation: {
                    keyboardNavigation: "off",
                    keyboard_direction: "vertical",
                    mouseScrollNavigation: "off",
                    mouseScrollReverse: "default",
                    onHoverStop: "off",
                    touch: {
                        touchenabled: "on",
                        touchOnDesktop: "off",
                        swipe_threshold: 75,
                        swipe_min_touches: 1,
                        swipe_direction: "horizontal",
                        drag_block_vertical: false
                    },
                    arrows: {
                        style: "uranus",
                        enable: true,
                        hide_onmobile: false,
                        hide_onleave: false,
                        tmp: '',
                        left: {
                            h_align: "left",
                            v_align: "center",
                            h_offset: 20,
                            v_offset: 0
                        },
                        right: {
                            h_align: "right",
                            v_align: "center",
                            h_offset: 20,
                            v_offset: 0
                        }
                    }
                },
                visibilityLevels: [1240, 1024, 778, 480],
                gridwidth: 1240,
                gridheight: 700,
                lazyType: "none",
                shadow: 0,
                spinner: "off",
                stopLoop: "off",
                stopAfterLoops: -1,
                stopAtSlide: -1,
                shuffle: "off",
                autoHeight: "off",
                hideThumbsOnMobile: "off",
                hideSliderAtLimit: 0,
                hideCaptionAtLimit: 0,
                hideAllCaptionAtLilmit: 0,
                debugMode: false,
                fallbacks: {
                    simplifyAll: "off",
                    nextSlideOnWindowFocus: "off",
                    disableFocusListener: false,
                }
            });
            var api = revapi41;

            var newCall = new Object(),
                cslide;

            newCall.callback = function() {
                var proc = api.revgetparallaxproc(),
                    fade = 1 + (proc * 1.7);
                fade2 = 1.3 + (proc * 2);

                fade = fade > 1 ? 1 : fade < 0 ? 0 : fade;
                fade2 = fade2 > 1 ? 1 : fade2 < 0.15 ? 0.15 : fade2;


                punchgs.TweenLite.set(api.find('.tp-giveeffect').parent(), {
                    opacity: fade
                });
                punchgs.TweenLite.set(api.find('.effect_wrapper'), {
                    opacity: fade2
                });
            }
            newCall.inmodule = "parallax";
            newCall.atposition = "start";


            api.bind("revolution.slide.onloaded", function(e) {
                api.find('.slotholder').wrap('<div class="effect_wrapper"></div>');
                api.revaddcallback(newCall);

            });
        }; /* END OF revapi call */



    }; /* END OF ON LOAD FUNCTION */
}()); /* END OF WRAPPING FUNCTION */