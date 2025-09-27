using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PruebaViamaticaJustinMoreira.Models;

namespace PruebaViamaticaJustinMoreira.Data;

public class ApplicationDbContext : IdentityDbContext<User>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Session> Sessions { get; set; }
    public DbSet<Person> Persons { get; set; }
    public DbSet<OptionsRoles> OptionsRoles { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<User>()
            .HasDiscriminator<string>("Discriminator")
            .HasValue<User>("User");

        // Configuraciones de relaciones
        builder.Entity<Session>()
            .HasOne(s => s.User)
            .WithMany(u => u.Sessions)
            .HasForeignKey(s => s.UserId);

        // Configuración completa de Person
        builder.Entity<Person>(entity =>
        {
            // Relación
            entity.HasOne(p => p.User)
                  .WithMany(u => u.Persons)
                  .HasForeignKey(p => p.UserId);

            // Tabla con trigger
            entity.ToTable("Persons", tb => tb.HasTrigger("tr_Persons_GenerateEmail"));
        });
    }
}
