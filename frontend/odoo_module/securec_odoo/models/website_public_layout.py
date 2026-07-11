# -*- coding: utf-8 -*-
"""Fix /web/login + website.layout when env.user is empty (Odoo 19 + website_sale)."""

from odoo import models


class Website(models.Model):
    _inherit = "website"

    def _compute_menu(self):
        # Anonymous backend login renders website.layout; website.menu then computes
        # is_visible (website_sale) which calls env.user._is_public(). If self.env has
        # no uid / empty user, that crashes. Run parent logic as public + sudo.
        pub = self.env(su=True).ref("base.public_user", raise_if_not_found=False)
        if pub:
            return super(Website, self.with_user(pub.id).sudo())._compute_menu()
        return super()._compute_menu()

    def _get_and_cache_current_cart(self):
        # website_sale: line (sale_order_sudo or not self.env.user._is_public()) assumes
        # env.user is a singleton; empty user on /web/login + website.layout crashes.
        if not self.env.user:
            pub = self.env(su=True).ref("base.public_user", raise_if_not_found=False)
            if pub:
                return super(Website, self.with_user(pub.id))._get_and_cache_current_cart()
        return super()._get_and_cache_current_cart()

    def has_ecommerce_access(self):
        if not self.env.user:
            pub = self.env(su=True).ref("base.public_user", raise_if_not_found=False)
            if pub:
                return super(Website, self.with_user(pub.id)).has_ecommerce_access()
        return super().has_ecommerce_access()
