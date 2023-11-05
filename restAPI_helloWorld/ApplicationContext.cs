using Microsoft.EntityFrameworkCore;
using restAPI_helloWorld;
using restAPI_helloWorld.models;

public class ApplicationContext : DbContext
{
    public DbSet<User> Users { get; set; } = null!;

    public ApplicationContext()
    {
        Database.EnsureCreated();
    }
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        Settings settings = new Settings();
        optionsBuilder.UseNpgsql($"Host={settings.host};Port={settings.port};Database={settings.database};Username={settings.username};Password={settings.password}");
    }
}
