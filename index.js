"use strict";

exports.register = function () {
  this.load_haraka-plugin-dkim_ini();

  // register hooks here. More info at https://haraka.github.io/core/Plugins/
  // this.register_hook('data_post', 'do_stuff_with_message')
};

exports.load_haraka-plugin-dkim_ini = function () {
  this.cfg = this.config.get(
    "haraka-plugin-dkim.ini",
    {
      booleans: [
        "+enabled", // this.cfg.main.enabled=true
        "-disabled", // this.cfg.main.disabled=false
        "+feature_section.yes", // this.cfg.feature_section.yes=true
      ],
    },
    () => {
      this.load_example_ini();
    },
  );
};
