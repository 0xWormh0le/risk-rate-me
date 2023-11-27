from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import Profile, DomainProfile


class DomainProfileAdmin(admin.StackedInline):
    model = DomainProfile
    verbose_name_plural = 'domains'


# Define an inline admin descriptor for Profile model
# which acts a bit like a singleton
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    inlines = (DomainProfileAdmin,)


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'
    inlines = (DomainProfileAdmin, )
    list_select_related = ('domain  ',)

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(ProfileInline, self).get_inline_instances(request, obj)


class CustomUserAdmin(UserAdmin):
    inlines = (ProfileInline, )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    list_select_related = ('profile', )

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
