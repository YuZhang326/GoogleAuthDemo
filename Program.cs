using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using GoogleAuthDemo.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

// Set attribute
builder.Services.Configure<IdentityOptions>(options =>
{
    // The password must contain at least one digit
    options.Password.RequireDigit = true;
    // The password must contain at least 12 characters
    options.Password.RequiredLength = 12;
    // The password must contain at least one uppercase letter
    options.Password.RequireUppercase = true;
    // The password must contain at least one non-alphanumeric 
    //      character (such as special characters such as!). @#$%^&*)
    options.Password.RequireNonAlphanumeric = true;

    // Enabling locking for new users improves security and 
    //      prevents new users from making a large number of false attempts in the initial phase
    options.Lockout.AllowedForNewUsers = true;
    // Increase account security by limiting the number of incorrect attempts users can make in a short period of time
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    // Temporarily lock users after multiple false attempts to prevent brute-force attacks
    options.Lockout.MaxFailedAccessAttempts = 5;

    // User emails are not required to be unique
    options.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    // Set the Cookie to HttpOnly
    options.Cookie.HttpOnly = true;
    // Set the expiration time of the Cookie to 5 minutes
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

    // Set the path to the login page
    options.LoginPath = "/Identity/Account/Login";
    // Set the path when access is denied
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    // If the user is active within the current expiration time, 
    //    the expiration time is reset. This way, 
    //    users' sessions will remain active while they remain active
    options.SlidingExpiration = true;
});

builder.Services.AddAuthentication()
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:Client"];
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// 2
/*
Enable authentication: 
  This code registers the authentication middleware to take effect in the 
  request processing pipeline. This middleware checks the authentication information for the 
  incoming request and sets the identity of the current user (if the authentication is successful).
Add to request pipeline:
  app.UseAuthentication(); Must be used in app.UseAuthorization(); 
  Call before to ensure that authentication takes place before authorization.
*/
app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
