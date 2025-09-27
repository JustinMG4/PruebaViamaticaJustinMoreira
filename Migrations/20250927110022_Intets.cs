using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PruebaViamaticaJustinMoreira.Migrations
{
    /// <inheritdoc />
    public partial class Intets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Intents",
                table: "Sessions",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Intents",
                table: "Sessions");
        }
    }
}
