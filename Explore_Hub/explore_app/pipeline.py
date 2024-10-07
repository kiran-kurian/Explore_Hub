def set_role(backend, user, response, *args, **kwargs):
    from explore_app.models import CustomUser
    
    # Ensure the user has a CustomUser profile
    custom_user, created = CustomUser.objects.get_or_create(user_ptr=user)

    # Set the role to 'reguser'
    custom_user.role = 'reguser'
    custom_user.save()
    session = kwargs['request'].session
    session['normal'] = user.id
    return