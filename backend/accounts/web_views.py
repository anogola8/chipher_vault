from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages

User = get_user_model()

def register_page(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        
        if len(password) < 10:
            return render(request, 'register.html', {'error': 'Password must be at least 10 characters.'})
            
        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {'error': 'Email already registered.'})
            
        User.objects.create_user(email=email, password=password)
        messages.success(request, "Account created. Please log in.")
        return redirect('login')
        
    return render(request, 'register.html')
