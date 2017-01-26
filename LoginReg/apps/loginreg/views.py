from django.shortcuts import render, redirect
from .models import User
import bcrypt
import re
from django.contrib import messages
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

def index(request):
    # User.objects.all().delete()
    return render(request, "loginreg/index.html")

def register(request):
    if request.method != 'POST':
        print("You have gotten to this page by invalid means!")
        return redirect('/')
    wrong=False
    fname = request.POST['first_name'].lower()
    lname = request.POST['last_name'].lower()
    email = request.POST['email']
    password = request.POST['password'].encode()
    confirm_password = request.POST['confirm_password'].encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    if len(fname) < 1:
        wrong = True
        messages.warning(request, "First name cannot be blank!")
    if len(lname) <1 :
        wrong = True
        messages.warning(request, "Last name cannot be blank!")
    if len(email) < 1:
        wrong = True
        messages.warning(request, "Email cannot be blank!")
    if not EMAIL_REGEX.match(email):
        wrong = True
        messages.warning(request, "Email is invalid!")
    if len(password) < 8:
        wrong = True
        messages.warning(request, "Password must be at least 8 characters!")
    if password != confirm_password:
        wrong = True
        messages.warning(request, "Your passwords must match!")
    if len(fname)>1 and len(lname)>1 and (not fname.isalpha() or not lname.isalpha()):
        wrong = True
        messages.warning(request, "Names must consist of letters ONLY!")

    if wrong:
        return redirect('/')
    else:
        messages.success(request, "Registration successful")
        print "---------->"+hashed
        User.objects.create(first_name = request.POST['first_name'], last_name = request.POST['last_name'], email = request.POST['email'], password= hashed)
        return redirect('/')

def login(request):
    email = request.POST['email']
    password = request.POST['password']
    email_list = User.objects.filter(email = email)
    print ""
    print email_list
    print ""
    hashed = email_list[0].password
    if email_list:
        if bcrypt.hashpw(password.encode(), hashed.encode()) == hashed.encode():
            request.session['id'] = email_list[0].id
            request.session['first_name'] = email_list[0].first_name
            return redirect('/success')
        else:
            print ("GOOD USERNAME BUT WRONG PASSWORD")
            return redirect('/')
    else:
        print ("THERE IS NO USER WITH THAT EMAIL REGISTERED")
        return redirect('/')

def success(request):
    return render(request,'loginreg/success.html')
