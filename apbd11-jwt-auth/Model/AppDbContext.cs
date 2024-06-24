using Microsoft.EntityFrameworkCore;

namespace apbd11_jwt_auth.Model
{
    public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext
    {
        public AppDbContext()
        {

        }

        public AppDbContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<AppUser> Users { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            // optionsBuilder.UseSqlServer("Server=localhost;Database=apbd11");
            optionsBuilder.UseSqlServer(@"Server=(localdb)\mssqllocaldb;Database=apbd11;Trusted_Connection=True;");
        }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<AppUser>().HasKey(u => u.IdUser);
            modelBuilder.Entity<AppUser>().Property(u => u.Login).IsRequired();
            modelBuilder.Entity<AppUser>().Property(u => u.Email).IsRequired();
            modelBuilder.Entity<AppUser>().Property(u => u.Password).IsRequired();
            modelBuilder.Entity<AppUser>().Property(u => u.Salt).IsRequired();
            modelBuilder.Entity<AppUser>().Property(u => u.RefreshToken).IsRequired();
            modelBuilder.Entity<AppUser>().Property(u => u.RefreshTokenExp).IsRequired();
        }

    }
}
